import asyncio
import logging
import time
import os
import base64
from collections import deque
from wstan.autobahn.websocket.protocol import parseHttpHeader
from wstan.autobahn.asyncio import create_sock
from wstan.autobahn.asyncio.websocket import WebSocketClientProtocol, WebSocketClientFactory
from wstan.relay import RelayMixin
from wstan import (parse_socks_addr, loop, config, can_return_error_page, die,
                   gen_error_page, get_sha1, make_socks_addr, http_die_soon, is_http_req)


# noinspection PyAttributeOutsideInit
class CustomWSClientProtocol(WebSocketClientProtocol):
    """Add auto-ping switch (dirty way) and let us manually start handshaking."""
    # this framework mix camel and underline naming style, nice!
    def __init__(self):
        WebSocketClientProtocol.__init__(self)
        self.customUriPath = '/'
        self.customWsKey = None
        self.delayedHandshake = asyncio.Future()

    def enableAutoPing(self, interval):
        self.autoPingInterval = interval
        self.autoPingPendingCall = loop.call_later(interval, self._sendAutoPing)

    def disableAutoPing(self):
        self.autoPingInterval = 0
        if self.autoPingPendingCall:
            self.autoPingPendingCall.cancel()
            self.autoPingPendingCall = None

    def startHandshake(self):
        """Delay handshake because some states must be set right before handshake (so
        they can't be set in factory)."""
        self.delayedHandshake.set_result(None)

    @asyncio.coroutine
    def restartHandshake(self):
        """Resume delayed handshake. It enable us to customize handshake HTTP header."""
        yield from asyncio.wait_for(self.delayedHandshake, None)
        if config.compatible:
            self.websocket_key = base64.b64encode(os.urandom(16))
        else:
            self.websocket_key = self.customWsKey
        request = [
            'GET %s HTTP/1.1' % self.customUriPath,
            'Host: %s:%d' % (self.factory.host, self.factory.port),
            'User-Agent: wwww',
            'Sec-WebSocket-Key: %s' % self.websocket_key.decode(),
            'Sec-WebSocket-Version: %d' % self.SPEC_TO_PROTOCOL_VERSION[self.version],
            'Pragma: no-cache',
            'Cache-Control: no-cache',
            'Connection: Upgrade',
            'Upgrade: WebSocket',
            '',
            ''  # ends with \r\n\r\n
        ]
        if config.compatible:
            # store custom ws key in cookie to prevent it from being changed by ws proxy
            request.insert(2, 'Cookie: %s=%s' % (config.cookie_key, self.customWsKey.decode()))
        self.http_request_data = '\r\n'.join(request).encode('utf8')
        self.sendData(self.http_request_data)
        if self.debug:
            self.log.debug(request)


class WSTunClientProtocol(CustomWSClientProtocol, RelayMixin):
    POOL_MAX_SIZE = 16
    TUN_MAX_IDLE_TIMEOUT = 35  # close tunnel in pool on timeout (in seconds)
    TUN_PING_INTERVAL = 8  # only tunnels in pool do auto-ping
    POOL_NOM_SIZE, TUN_MIN_IDLE_TIMEOUT = round(POOL_MAX_SIZE / 2), round(TUN_MAX_IDLE_TIMEOUT / 2)
    pool = deque()

    def __init__(self):
        CustomWSClientProtocol.__init__(self)
        RelayMixin.__init__(self)
        self.lastIdleTime = None
        self.checkTimeoutTask = None
        self.tunOpen = asyncio.Future()
        self.inPool = False
        self.canReturnErrorPage = False
        nonce = os.urandom(16)
        if not config.tun_ssl:
            self.initCipher(nonce, encryptor=True)
        self.customWsKey = base64.b64encode(nonce)  # nonce used to encrypt in B64

    if TUN_MAX_IDLE_TIMEOUT <= 0:
        def resetTunnel(self, reason=''):
            self.sendClose(1000)

        def onResetTunnel(self):
            self.sendClose(1000)

    def succeedReset(self):
        super().succeedReset()
        self.lastIdleTime = time.time()
        WSTunClientProtocol.addToPool(self)

    def onOpen(self):
        self.tunOpen.set_result(None)
        self.lastIdleTime = time.time()
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
            msg = self.parseResetMessage(dat)
            if not msg.startswith('  '):
                logging.info('tunnel abnormal reset: %s' % msg)
                if self.canReturnErrorPage:
                    title, __, reason = msg.partition(':')
                    self._writer.write(gen_error_page(title, reason.strip()))
            self.onResetTunnel()
        elif cmd == self.CMD_DAT:
            dat = self.decrypt(dat[1:])
            if self.tunState != self.TUN_STATE_USING:
                # why this happens?
                return
            self.canReturnErrorPage = False
            self._writer.write(dat)
        else:
            logging.error('wrong command')

    def onClose(self, *args):
        if not self.tunOpen.done():
            RelayMixin.onClose(self, *args, logWarn=False)
            self.tunOpen.cancel()
        else:
            RelayMixin.onClose(self, *args)
        if self.inPool:
            self.pool.remove(self)

    @classmethod
    @asyncio.coroutine
    def _checkTimeout(cls, tun):
        while tun.state == cls.STATE_OPEN:
            timeout = (cls.TUN_MAX_IDLE_TIMEOUT if len(cls.pool) <= cls.POOL_NOM_SIZE else
                       cls.TUN_MIN_IDLE_TIMEOUT)
            yield from asyncio.sleep(timeout)
            if (tun.tunState == cls.TUN_STATE_IDLE and
               (time.time() - tun.lastIdleTime) > timeout):
                tun.sendClose(1000)

    @classmethod
    def addToPool(cls, tun):
        assert tun.tunState == cls.TUN_STATE_IDLE
        if len(cls.pool) >= cls.POOL_MAX_SIZE:
            tun.sendClose(1000)
        else:
            assert not tun.checkTimeoutTask
            tun.checkTimeoutTask = asyncio.async(cls._checkTimeout(tun))
            tun.inPool = True
            tun.enableAutoPing(cls.TUN_PING_INTERVAL)
            cls.pool.append(tun)

    @classmethod
    @asyncio.coroutine
    def startProxy(cls, addrHeader, dat, reader, writer):
        canErr = can_return_error_page(dat)

        if cls.pool:
            logging.debug('reuse tunnel from pool (total %s)' % len(cls.pool))
            tun = cls.pool.popleft()
            tun.checkTimeoutTask.cancel()
            tun.checkTimeoutTask = None
            tun.inPool = False
            tun.disableAutoPing()
            tun.sendMessage(tun.makeRelayHeader(addrHeader, dat), True)
        else:
            try:
                sock = None
                if config.proxy:
                    sock = yield from setup_http_tunnel()

                tun = (yield from loop.create_connection(
                    factory, None if sock else config.uri_addr, None if sock else config.uri_port,
                    server_hostname=config.uri_addr if config.tun_ssl else None,
                    sock=sock, ssl=config.tun_ssl))[1]
                # lower latency by sending relay header and data in ws handshake
                tun.customUriPath = '/' + base64.urlsafe_b64encode(tun.makeRelayHeader(addrHeader, dat)).decode()
                asyncio.async(tun.restartHandshake())
                yield from asyncio.wait_for(tun.tunOpen, tun.openHandshakeTimeout)
            except Exception as e:
                if isinstance(e, (asyncio.TimeoutError, asyncio.CancelledError)):
                    # sometimes reason can be None in extremely poor network
                    msg = tun.wasNotCleanReason or ''
                else:
                    msg = str(e)
                msg = translate_err_msg(msg)
                logging.error("can't connect to server: %s" % msg)
                if canErr:
                    writer.write(gen_error_page("can't connect to wstan server", msg))
                return writer.close()
        tun.canReturnErrorPage = canErr
        tun.setProxy(reader, writer)


factory = WebSocketClientFactory(config.uri)
factory.protocol = WSTunClientProtocol
factory.useragent = ''
factory.autoPingTimeout = 5
factory.openHandshakeTimeout = 8  # timeout after TCP established and before succeeded WS handshake


def translate_err_msg(msg):
    # Windows error code reference: https://support.microsoft.com/en-us/kb/819124
    if msg == '[Errno -2] Name or service not known':
        return 'host not found'
    elif msg == 'WebSocket connection upgrade failed (400 - None)':
        return 'forbidden (maybe key is wrong or system clock is out of sync)'
    elif 'getaddrinfo failed' in msg:
        return 'DNS lookup failed'
    elif (msg.startswith('[Errno 10060] Conn') or
          msg == 'peer did not finish (in time) the opening handshake'):
        # failed to establish TCP connection or handshake timeout, because of poor network
        return 'connection timed out'
    elif msg.startswith('[Errno 10061] Conn'):
        return 'connection refused'
    else:
        return msg


# functions below assume one send cause one recv, because server is at localhost (except HTTP part)

@asyncio.coroutine
def dispatch_proxy(reader, writer):
    dat = yield from reader.read(2048)
    if not dat:
        return writer.close()
    handler = socks5_tcp_handler if dat[0] == 0x05 else http_proxy_handler
    try:
        yield from handler(dat, reader, writer)
    except ConnectionError:
        writer.close()


@asyncio.coroutine
def http_proxy_handler(dat, reader, writer):
    if not is_http_req(dat):
        logging.warning('bad http proxy request')
        return writer.close()

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
        host, port = url.decode().split(':')
        port = int(port)
    else:  # e.g. http://g.cn/aa
        url = url[7:]
        i = url.find(b'/')
        path = url[i:]
        host, *port = url[:i].split(b':')
        port = int(port[0]) if port else 80
        host = host.decode()
    logging.info('requesting %s:%d' % (host, port))
    addr_header = make_socks_addr(host, port) 

    if method == b'CONNECT':
        writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        dat = yield from reader.read(2048)
        if not dat:
            return writer.close()
    else:
        dat = method + b' ' + path + b' ' + ver + rest_dat
        dat = http_die_soon(dat)  # let target know keep-alive is not supported

    yield from WSTunClientProtocol.startProxy(addr_header, dat, reader, writer)


@asyncio.coroutine
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
    logging.info('requesting %s:%d' % (target_addr, target_port))
    if cmd != 0x01:  # CONNECT
        writer.write(b'\x05\x07\x00\x01' + b'\x00' * 6)  # \x07 == COMMAND NOT SUPPORTED
        return writer.close()

    # By accepting request before connected to target delay can be lowered (of a round-trip).
    # But SOCKS client can't get real reason when error happens (Firefox always display
    # connection reset error). Dirty solution: generate a HTML page when a HTTP request failed
    writer.write(b'\x05\x00\x00\x01' + b'\x01' * 6)  # \x00 == SUCCEEDED
    dat = yield from reader.read(2048)
    if not dat:
        return writer.close()

    yield from WSTunClientProtocol.startProxy(addr_header, dat, reader, writer)


@asyncio.coroutine
def setup_http_tunnel():
    sock = yield from create_sock(config.proxy_host, config.proxy_port)
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


def main():
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
