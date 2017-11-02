import asyncio
import logging
import time
import os
import base64
from asyncio import coroutine, async_, wait_for, sleep, CancelledError
from collections import deque
from urllib import parse as urlparse
from wstan.autobahn.util import makeHttpResp
from wstan.autobahn.websocket.protocol import parseHttpHeader
from wstan.autobahn.asyncio.websocket import WebSocketClientProtocol, WebSocketClientFactory
from wstan.relay import RelayMixin
from wstan import (parse_socks_addr, loop, config, can_return_error_page, die,
                   gen_error_page, get_sha1, http_die_soon, is_http_req,
                   my_sock_connect, InMemoryLogHandler, __version__)


# noinspection PyAttributeOutsideInit
class CustomWSClientProtocol(WebSocketClientProtocol):
    """Add auto-ping switch (dirty way) and let us start handshaking manually."""
    # this framework mix camel and underline naming style, nice!
    def __init__(self):
        WebSocketClientProtocol.__init__(self)
        self.customUriPath = '/'
        self.customWsKey = None
        self.http_request_data = None
        self.noSendHandshake = False
        self.lastPingSentTime = None

    def setAutoPing(self, interval, timeout):
        """Set auto-ping interval. Start it if it's not running."""
        self.disableAutoPing()
        self.autoPingInterval = interval
        self.autoPingTimeout = timeout
        self.autoPingPendingCall = loop.call_later(interval, self._sendAutoPing)

    def _sendAutoPing(self):
        super()._sendAutoPing()
        self.lastPingSentTime = time.time()

    def disableAutoPing(self):
        if self.autoPingPendingCall:
            self.autoPingPendingCall.cancel()
            self.autoPingPendingCall = None

    def startHandshake(self):
        if self.http_request_data is not None:
            return

        if config.compatible:
            self.websocket_key = base64.b64encode(os.urandom(16))
        else:
            self.websocket_key = self.customWsKey
        request = [
            'GET %s HTTP/1.1' % self.customUriPath,
            'Host: %s:%d' % (self.factory.host, self.factory.port),
            'Sec-WebSocket-Key: %s' % self.websocket_key.decode(),
            'Sec-WebSocket-Version: %d' % self.SPEC_TO_PROTOCOL_VERSION[self.factory.version],
            'Pragma: no-cache',
            'Cache-Control: no-cache',
            'Connection: Upgrade',
            'Upgrade: WebSocket',
            ]
        if config.compatible:
            # store custom ws key in cookie to prevent it from being changed by ws proxy
            request.append('Cookie: %s=%s' % (config.cookie_key, self.customWsKey.decode()))
        if self.factory.useragent:
            request.append('User-Agent: %s' % self.factory.useragent)
        self.http_request_data = '\r\n'.join(request).encode('utf8') + b'\r\n\r\n'
        if not self.noSendHandshake:
            self.sendData(self.http_request_data)


class WSTunClientProtocol(CustomWSClientProtocol, RelayMixin):
    POOL_MAX_SIZE = 16
    POOL_NOM_SIZE = round(POOL_MAX_SIZE / 2)
    MAX_RETRY_COUNT = 5
    TUN_MAX_IDLE_TIMEOUT = 60  # close tunnels in pool on timeout (in seconds)
    TUN_MIN_IDLE_TIMEOUT = round(TUN_MAX_IDLE_TIMEOUT / 2)  # used when len(pool) > POOL_NOM_SIZE
    # Tunnels in-use also need auto-ping. If another end dead when resetting,
    # then those zombie connections will never close?
    TUN_AUTO_PING_INTERVAL = 400
    TUN_AUTO_PING_TIMEOUT = 30
    POOL_AUTO_PING_INTERVAL = 10  # in-pool connection fail faster
    POOL_AUTO_PING_TIMEOUT = 6
    PUSH_TO_TUN_CONN_ERR_MSG = 'connection to user-agent broken'
    rtt = None  # smoothed RTT
    pool = deque()

    def __init__(self):
        CustomWSClientProtocol.__init__(self)
        RelayMixin.__init__(self)
        self.lastIdleTime = None
        self.retryCount = 0
        self.checkTimeoutTask = None
        self.inPool = False
        self.canReturnErrorPage = False
        nonce = os.urandom(16)
        if not config.tun_ssl:
            self.initCipher(nonce, encryptor=True)
        self.customWsKey = base64.b64encode(nonce)  # nonce used to encrypt in base64

    if TUN_MAX_IDLE_TIMEOUT <= 0 or POOL_MAX_SIZE <= 0:
        def resetTunnel(self, reason=''):
            # skip sending reset command, close directly instead
            self.tunState = self.TUN_STATE_RESETTING
            self.sendClose(1000)

        def onResetTunnel(self):
            self.tunState = self.TUN_STATE_IDLE
            self.sendClose(1000)

    def succeedReset(self):
        super().succeedReset()
        self.lastIdleTime = time.time()
        self.addToPool()

    def onOpen(self):
        self.tunOpen.set_result(None)

        self.lastIdleTime = time.time()
        self.startPushToTunLoop()
        self.setAutoPing(self.TUN_AUTO_PING_INTERVAL, self.TUN_AUTO_PING_TIMEOUT)
        if not config.debug:
            self.customUriPath = None  # save memory
        if not config.tun_ssl:
            if config.compatible:
                nonce = get_sha1(base64.b64decode(self.customWsKey))[:16]
            else:
                # SHA-1 has 20 bytes
                nonce = base64.b64decode(self.http_headers['sec-websocket-accept'])[:16]
            self.initCipher(nonce, decryptor=True)

    def onMessage(self, dat, isBinary):
        if not isBinary:
            logging.error('non binary ws message received')
            return self.sendClose(3000)

        cmd = ord(self.decrypt(dat[:1]))
        if cmd == self.CMD_RST:
            reason, err = self.parseResetMessage(dat)
            if reason:
                err = translate_err_msg(err)
                logging.info('%s: %s' % (reason, err))
                if self.canReturnErrorPage:
                    self._writer.write(gen_error_page(reason, err))
            self.onResetTunnel()
        elif cmd == self.CMD_DAT:
            dat = self.decrypt(dat[1:])
            if self.tunState != self.TUN_STATE_USING:
                if self.tunState == self.TUN_STATE_IDLE:
                    logging.debug('IDLE should not appear here!')
                # Reset command sent, but server will keep sending data before
                # receiving the command.
                # Can't just throw away dat, because decryptor need to be updated
                return
            self.canReturnErrorPage = False
            self._writer.write(dat)
        else:
            logging.error('wrong command')

    def onPong(self, _):
        self.updateRtt(time.time() - self.lastPingSentTime)

    def onClose(self, *args):
        if not self.tunOpen.done():
            self._writer = None  # prevent it from being closed, openTunnel will close it
            RelayMixin.onClose(self, *args, logWarn=False)
            self.tunOpen.cancel()
        else:
            RelayMixin.onClose(self, *args)
        self.tryRemoveFromPool()

    @coroutine
    def _checkTimeout(self):
        while self.state == self.STATE_OPEN:
            timeout = (self.TUN_MAX_IDLE_TIMEOUT if len(self.pool) <= self.POOL_NOM_SIZE else
                       self.TUN_MIN_IDLE_TIMEOUT)
            yield from sleep(timeout)
            if (self.tunState == self.TUN_STATE_IDLE and
               (time.time() - self.lastIdleTime) > timeout):
                self.tryRemoveFromPool()  # avoid accidentally using a closing tunnel
                self.sendClose(1000)

    def tryRemoveFromPool(self):
        if self.inPool:
            self.pool.remove(self)
            self.inPool = False

    def addToPool(self):
        assert self.tunState == self.TUN_STATE_IDLE
        if len(self.pool) >= self.POOL_MAX_SIZE:
            self.sendClose(1000)
        else:
            assert not self.checkTimeoutTask
            self.checkTimeoutTask = async_(self._checkTimeout())
            self.inPool = True
            self.setAutoPing(self.POOL_AUTO_PING_INTERVAL, self.POOL_AUTO_PING_TIMEOUT)
            self.pool.append(self)

    @classmethod
    def updateRtt(cls, rtt):
        if cls.rtt is None:
            cls.rtt = rtt
        else:
            cls.rtt = 0.8 * cls.rtt + 0.2 * rtt

    @classmethod
    @coroutine
    def openTunnel(cls, target, dat, reader, writer, retryCount=0):
        logging.info('requesting %s:%d' % target)

        if not dat:
            logging.debug('openTunnel with no data')
        canErr = can_return_error_page(dat)

        if cls.pool:  # reuse from pool
            logging.debug('reuse tunnel from pool (total %s)' % len(cls.pool))
            tun = cls.pool[0]
            tun.checkTimeoutTask.cancel()
            tun.checkTimeoutTask = None
            tun.tryRemoveFromPool()
            tun.setAutoPing(cls.TUN_AUTO_PING_INTERVAL, cls.TUN_AUTO_PING_TIMEOUT)
            tun.canReturnErrorPage = canErr
            tun.setProxy(reader, writer)
            tun.sendMessage(tun.makeRelayHeader(target, dat), True)
            return

        # new tunnel
        try:
            if retryCount >= cls.MAX_RETRY_COUNT:
                raise ConnectionResetError('run into tcp reset, all retries failed')

            sock = None
            if config.proxy:
                sock = yield from setup_http_tunnel()

            tun = factory()
            # Lower latency by sending relay header and data in ws handshake
            tun.customUriPath = factory.path + base64.urlsafe_b64encode(
                tun.makeRelayHeader(target, dat)).decode()
            tun.canReturnErrorPage = canErr
            # Data may arrive before setProxy if wait for tunOpen here and then set proxy.
            tun.setProxy(reader, writer, startPushLoop=False)  # push loop will start in onOpen

            if config.tfo:
                assert not config.proxy and not config.tun_ssl
                tun.noSendHandshake = True
                tun.startHandshake()
                # tfo is meaningless if handshake data can't fit into TCP SYN packet
                # switch back to normal sock_connect just in case my Windows tfo extension has bug
                tfoDat = tun.http_request_data if len(tun.http_request_data) <= 1400 else None
                sock = yield from my_sock_connect(config.uri_addr, config.uri_port, tfo_dat=tfoDat)
                # it will return after SYN,ACK received regardless of TFO
                if not tfoDat:
                    loop.sock_sendall(sock, tun.http_request_data)

            yield from loop.create_connection(
                lambda: tun, None if sock else config.uri_addr, None if sock else config.uri_port,
                server_hostname=config.uri_addr if config.tun_ssl else None,
                sock=sock, ssl=config.tun_ssl)
        except Exception as e:
            msg = translate_err_msg(str(e))
            dest = 'proxy' if config.proxy and not sock else 'wstan server'
            logging.error("can't connect to %s: %s" % (dest, msg))
            if canErr:
                writer.write(gen_error_page("can't connect to " + dest, msg))
            return writer.close()

        try:
            yield from wait_for(tun.tunOpen, None)
        except CancelledError:
            # sometimes reason can be None in extremely poor network
            msg = tun.wasNotCleanReason or ''

            if isinstance(tun.connLostReason, ConnectionResetError):
                # GFW random reset HTTP stream it can't recognize, just retry
                return async_(cls.openTunnel(target, dat, reader, writer, retryCount+1))

            msg = translate_err_msg(msg)
            logging.error("can't connect to server: %s" % msg)
            if tun.wasNotCleanReason and tun.canReturnErrorPage:  # write before closing writer
                writer.write(gen_error_page("can't connect to wstan server", msg))
            return writer.close()

        if retryCount > 0:
            logging.debug('tcp reset happen, retried %d times' % retryCount)


def translate_err_msg(msg):
    # Windows error code reference: https://support.microsoft.com/en-us/kb/819124
    if msg in ('[Errno -2] Name or service not known',
               '[Errno -5] No address associated with hostname'):
        return 'non-existent domain'
    elif msg.startswith('WebSocket connection upgrade failed (400'):
        return 'forbidden (maybe key is wrong or system clock is out of sync)'
    elif 'getaddrinfo failed' in msg:
        return 'DNS lookup failed'
    elif (msg.startswith('[Errno 10060] Conn') or
          msg == 'peer did not finish (in time) the opening handshake' or
          msg.startswith('[Errno 110] Connect call failed') or
          msg.startswith('[WinError 121]')):
        # failed to establish TCP connection or handshake timeout, because of poor network
        return 'connection timed out'
    elif msg.startswith('[Errno 10061] Conn') or msg.startswith('[Errno 111] Connect call failed'):
        return 'connection refused'
    else:
        return msg


def gen_log_view_page():
    if logViewTemplate is None:
        txt = 'wstan log (latest 200, descending):\n\n' + \
              '\n'.join(reversed(InMemoryLogHandler.logs))
        return makeHttpResp(txt, type_='text/plain')
    else:
        return makeHttpResp(logViewTemplate.render(version=__version__,
                                                   logs=tuple(reversed(InMemoryLogHandler.logs)),
                                                   rtt=WSTunClientProtocol.rtt))

# functions below assume one send cause one recv, because server is at localhost (except HTTP part)


@coroutine
def dispatch_proxy(reader, writer):
    """Handle requests from User-Agent."""
    dat = yield from reader.read(2048)
    if not dat:
        return writer.close()

    if dat[0] == 0x04:
        logging.warning('unsupported SOCKS v4 request')
        return writer.close()
    elif dat[0] == 0x05:
        handler = socks5_tcp_handler
    elif is_http_req(dat):
        handler = http_proxy_handler
    else:
        logging.warning('unknown request')
        return writer.close()

    try:
        yield from handler(dat, reader, writer)
    except ConnectionError:
        writer.close()


@coroutine
def http_proxy_handler(dat, reader, writer):
    # get request line and header
    while True:  # the line is not likely to be that long
        if b'\r\n\r\n' in dat:
            break
        r = yield from reader.read(1024)
        if not r:
            return writer.close()
        dat += r
    rl_end = dat.find(b'\r\n')
    req_line, rest_dat = dat[:rl_end], dat[rl_end:]

    method, url, ver = req_line.split()
    if method == b'CONNECT':  # e.g. g.cn:443
        host, port = url.split(b':')
        port = int(port)
    elif url.startswith(b'http'):  # e.g. http://g.cn/aa
        parsed = urlparse.urlparse(url)
        path, host, port = parsed.path, parsed.hostname, parsed.port or 80
    else:
        writer.write(gen_log_view_page())
        return writer.close()

    if method == b'CONNECT':
        writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        try:
            dat = yield from wait_for(reader.read(2048), 0.02)
            if not dat:
                return writer.close()
        except asyncio.TimeoutError:
            dat = None
    else:
        dat = method + b' ' + path + b' ' + ver + rest_dat
        dat = http_die_soon(dat)  # let target know keep-alive is not supported

    async_(WSTunClientProtocol.openTunnel((host.decode(), port), dat, reader, writer))


@coroutine
def socks5_tcp_handler(dat, reader, writer):
    # handle auth method selection
    if len(dat) < 2 or len(dat) != dat[1] + 2:
        logging.warning('bad SOCKS v5 request')
        return writer.close()
    writer.write(b'\x05\x00')  # \x00 == NO AUTHENTICATION REQUIRED

    # handle relay request
    dat = yield from reader.read(262)
    try:
        cmd, addr_header = dat[1], dat[2:]
        target_addr, target_port = parse_socks_addr(addr_header)
    except (ValueError, IndexError):
        logging.warning('invalid SOCKS v5 relay request')
        return writer.close()
    if cmd != 0x01:  # CONNECT
        writer.write(b'\x05\x07\x00\x01' + b'\x00' * 6)  # \x07 == COMMAND NOT SUPPORTED
        return writer.close()

    # Delay can be lowered (of a round-trip) by accepting request before connected to target.
    # But SOCKS client can't get real reason when error happens (not a big problem, Firefox always
    # display connection reset error). Dirty solution: generate a HTML page when a HTTP request failed
    writer.write(b'\x05\x00\x00\x01' + b'\x01' * 6)  # \x00 == SUCCEEDED
    try:
        dat = yield from wait_for(reader.read(2048), 0.02)
        if not dat:
            return writer.close()
    except asyncio.TimeoutError:
        # 20ms passed and no data received, rare but legal behavior.
        # timeout may always happen if set to 10ms, and enable asyncio library debug mode will "fix" it
        # e.g. Old SSH client will wait for server after conn established
        dat = None

    async_(WSTunClientProtocol.openTunnel((target_addr, target_port), dat, reader, writer))


@coroutine
def setup_http_tunnel():
    sock = yield from my_sock_connect(config.proxy_host, config.proxy_port)
    pair = '%s:%d' % (config.uri_addr, config.uri_port)
    req = 'CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n' % (pair, pair)
    loop.sock_sendall(sock, req.encode())
    dat = yield from loop.sock_recv(sock, 4096)
    while True:
        end = dat.find(b'\r\n\r\n')
        if end != -1:
            break
        r = yield from loop.sock_recv(sock, 4096)
        if not r:
            return
        dat += r

    http_response_data = dat[:end+4]
    http_status_line, http_headers, __ = parseHttpHeader(http_response_data)
    logging.debug("received HTTP status line for proxy connect request: %s" % http_status_line)
    logging.debug("received HTTP headers for proxy connect request: %s" % http_headers)
    sl = http_status_line.split()
    if len(sl) < 2:
        raise ConnectionError("bad HTTP response status line '%s'" % http_status_line)
    try:
        status_code = int(sl[1].strip())
    except ValueError:
        raise ConnectionError("bad HTTP status code ('%s')" % sl[1].strip())
    if not (200 <= status_code < 300):
        # FIXME: handle redirects
        # FIXME: handle authentication required
        if len(sl) > 2:
            reason = " - %s" % ''.join(sl[2:])
        else:
            reason = ""
        raise ConnectionError("HTTP proxy connect failed (%d%s)" % (status_code, reason))
    if dat[end+4:]:
        logging.warning('got extra data in HTTP proxy resp: %s' % dat[end+4:])

    return sock


def silent_tpo_timeout_err_handler(loop_, context):
    """Prevent asyncio from logging annoying OSError when using TFO."""
    exc = context.get('exception')
    if not exc:
        return
    if hasattr(exc, 'winerror') and exc.winerror == 121:  # ERROR_SEM_TIMEOUT
        return
    loop_.default_exception_handler(context)


# load html template (optional) for web log viewer
try:
    import jinja2
    import pkg_resources
except ImportError:
    logViewTemplate = jinja2 = pkg_resources = None  # fallback to plain text version
else:
    logViewTemplate = jinja2.Template(
        pkg_resources.resource_string(__package__, 'logview.html').decode('utf-8'))


factory = WebSocketClientFactory(config.uri)
factory.protocol = WSTunClientProtocol
factory.useragent = ''
factory.openHandshakeTimeout = 8  # timeout after TCP established and before finishing WS handshake
factory.closeHandshakeTimeout = factory.serverConnectionDropTimeout = 4
if not factory.path.endswith('/'):
    factory.path += '/'


def main():
    if config.tfo:
        loop.set_exception_handler(silent_tpo_timeout_err_handler)

    try:
        server = loop.run_until_complete(
            asyncio.start_server(dispatch_proxy, 'localhost', config.port))
    except OSError:
        die('wstan client failed to bind on localhost:%d' % config.port)

    print('wstan client -- SOCKS5/HTTP(S) server listening on localhost:%d' % config.port)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        loop.close()
