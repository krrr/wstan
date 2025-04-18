# Copyright (c) 2025 krrr
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import asyncio
import logging
import time
import os
import base64
import socket
from asyncio import wait_for, sleep, create_task, CancelledError, StreamReader, StreamWriter
from asyncio.exceptions import IncompleteReadError
from collections import deque
from urllib import parse as urlparse
from wstan.autobahn.util import makeHttpResp
from wstan.autobahn.websocket.protocol import parseHttpHeader
from wstan.autobahn.asyncio.websocket import WebSocketClientProtocol, WebSocketClientFactory
from wstan.relay import RelayMixin
from wstan import (parse_socks5_addr, make_socks5_addr, loop, config, can_return_error_page, die,
                   gen_error_page, get_sha1, http_die_soon, is_http_req, parse_sock5_udp_addr,
                   my_sock_connect, InMemoryLogHandler, __version__)
from wstan.utils import open_udp_endpoint, UdpReader, UdpWriter, UdpEndpointClosedError

INIT_DATA_LEN = 2048
INIT_DATA_TIMEOUT = 0.03  # sec


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
    MAX_RETRY_COUNT = 5
    # Tunnels in-use also need auto-ping. If another end dead when resetting,
    # then those zombie connections will never close?
    TUN_AUTO_PING_INTERVAL = 400
    TUN_AUTO_PING_TIMEOUT = 30
    POOL_AUTO_PING_INTERVAL = 18  # in-pool connection fail faster
    POOL_AUTO_PING_TIMEOUT = 9
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
        self.poolMaxIdleTimeout = config.pool_max_idle  # close tunnels in pool on timeout (in seconds)
        self.poolMinIdleTimeout = round(config.pool_max_idle / 3)
        self.poolSize = config.pool_size
        nonce = os.urandom(16)
        if not config.tun_ssl:
            self.initCipher(nonce, encryptor=True)
        self.customWsKey = base64.b64encode(nonce)  # nonce used to encrypt in base64

    def resetTunnel(self, reason=''):
        if self.poolMaxIdleTimeout <= 0 or self.poolSize <= 0:
            # skip sending reset command, close directly instead
            self.tunState = self.TUN_STATE_RESETTING
            self.sendClose(1000)
        else:
            super().resetTunnel(reason)

    def onResetTunnel(self):
        if self.poolMaxIdleTimeout <= 0 or self.poolSize <= 0:
            # skip sending reset command, close directly instead
            self.tunState = self.TUN_STATE_IDLE
            self.sendClose(1000)
        else:
            super().onResetTunnel()

    def succeedReset(self):
        super().succeedReset()
        self.lastIdleTime = time.time()
        self.addToPool()

    def onOpen(self):
        self.tunOpen.set_result(None)

        self.lastIdleTime = time.time()
        self.startPushToTunLoop(self._exclusiveReader, self._exclusiveWriter)
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
                    self._exclusiveWriter.write(gen_error_page(reason, err))
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
            self._exclusiveWriter.write(dat)
        elif cmd == self.CMD_DGM:
            dat = self.decrypt(dat[1:])
            if self.tunState != self.TUN_STATE_USING:
                return
            self._exclusiveWriter.write(b'\x00\x00' + dat)  # RSV
        else:
            logging.error('wrong command')

    def onPong(self, _):
        self.updateRtt(time.time() - self.lastPingSentTime)

    def onClose(self, *args):
        if not self.tunOpen.done():
            self._exclusiveWriter = None  # prevent it from being closed, openTunnel will close it
            RelayMixin.onClose(self, *args, logWarn=False)
            self.tunOpen.cancel()
        else:
            RelayMixin.onClose(self, *args)
        self.tryRemoveFromPool()

    def setProxy(self, reader: StreamReader | UdpReader, writer: StreamWriter | UdpWriter, startPushLoop=True):
        super().setProxy(reader, writer, startPushLoop)
        self._exclusiveReader = reader
        self._exclusiveWriter = writer

    async def _pushToTunnelLoopUdp(self, reader: UdpReader, writer: UdpWriter):
        while True:
            try:
                pkt = await reader.read()
            except CancelledError:
                break
            except UdpEndpointClosedError:
                self.resetTunnel()
                break
            if pkt is None:
                self.resetTunnel()
                break
            target_addr, target_port, remain_idx = parse_sock5_udp_addr(pkt.data)
            dat = self.makeDatagramMessage((target_addr, target_port), pkt.data[remain_idx:])
            self.sendMessage(dat, True)
            await self.drain()

        writer.close()

    async def _checkIdleTimeout(self):
        while self.state == self.STATE_OPEN:
            # dynamic timeout
            timeout = self.poolMaxIdleTimeout - (len(self.pool) / self.poolSize) * (self.poolMaxIdleTimeout - self.poolMinIdleTimeout)
            await sleep(self.poolMinIdleTimeout / 2)
            if self.tunState == self.TUN_STATE_IDLE and (time.time() - self.lastIdleTime) > timeout:
                self.tryRemoveFromPool()  # avoid accidentally using a closing tunnel
                self.sendClose(1000)

    def tryRemoveFromPool(self):
        if self.inPool:
            self.pool.remove(self)
            self.inPool = False

    def addToPool(self):
        assert self.tunState == self.TUN_STATE_IDLE
        if len(self.pool) >= self.poolSize:
            self.sendClose(1000)
        else:
            assert not self.checkTimeoutTask
            self.checkTimeoutTask = create_task(self._checkIdleTimeout())
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
    async def openTunnel(cls, target: (str, int), initDat: bytes, reader: StreamReader | UdpReader,
                         writer: StreamWriter | UdpWriter, retryCount=0):
        is_udp = isinstance(reader, UdpReader)
        logging.info('requesting %s:%d %s' % (target[0], target[1], 'udp' if is_udp else ''))

        if not initDat:
            logging.debug('openTunnel with no data')
        canErr = not is_udp and can_return_error_page(initDat)

        if cls.pool:  # reuse from pool
            logging.debug('reuse tunnel from pool (total %s)' % len(cls.pool))
            tun = cls.pool[0]
            tun.checkTimeoutTask.cancel()
            tun.checkTimeoutTask = None
            tun.tryRemoveFromPool()
            tun.setAutoPing(cls.TUN_AUTO_PING_INTERVAL, cls.TUN_AUTO_PING_TIMEOUT)
            tun.canReturnErrorPage = canErr
            tun.setProxy(reader, writer)
            if is_udp:
                tun.sendMessage(tun.makeDatagramMessage(target, initDat), True)
            else:
                tun.sendMessage(tun.makeRelayHeader(target, initDat), True)
            return

        # new tunnel
        try:
            if retryCount >= cls.MAX_RETRY_COUNT:
                raise ConnectionResetError('run into tcp reset, all retries failed')

            sock = None
            if config.proxy:
                sock = await setup_http_tunnel()

            tun = factory()
            # Lower latency by sending relay header and data in ws handshake
            tun.customUriPath = factory.path + base64.urlsafe_b64encode(
                tun.makeRelayHeader(target, initDat, is_udp)).decode()
            tun.canReturnErrorPage = canErr
            # Data may arrive before setProxy if wait for tunOpen here and then set proxy.
            tun.setProxy(reader, writer, startPushLoop=False)  # push loop will start in onOpen

            await loop.create_connection(
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
            await wait_for(tun.tunOpen, None)
        except CancelledError:
            # sometimes reason can be None in extremely poor network
            msg = tun.wasNotCleanReason or ''

            if isinstance(tun.connLostReason, ConnectionResetError):
                # GFW random reset HTTP stream it can't recognize, just retry
                return create_task(cls.openTunnel(target, initDat, reader, writer, retryCount + 1))

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


async def dispatch_request(reader: StreamReader, writer: StreamWriter):
    """Handle requests from User-Agent."""
    try:
        dat = await reader.readexactly(2)

        if dat[0] == 0x05:
            handler = socks5_tcp_handler
        elif dat[0] == 0x05:
            handler = socks4_tcp_handler
        else:
            dat += await reader.readuntil(b' ')  # until space after method
            if is_http_req(dat):
                handler = http_proxy_handler
            else:
                logging.warning('unknown request')
                return writer.close()

        await handler(dat, reader, writer)
    except (ConnectionError, IncompleteReadError):
        return writer.close()


async def http_proxy_handler(dat: bytes, reader: StreamReader, writer: StreamWriter):
    # get request line and header
    dat += await reader.readuntil(b'\r\n\r\n')

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
            dat = await wait_for(reader.read(INIT_DATA_LEN), INIT_DATA_TIMEOUT)
            if not dat:
                return writer.close()
        except asyncio.TimeoutError:
            dat = None
    else:
        dat = method + b' ' + path + b' ' + ver + rest_dat
        dat = http_die_soon(dat)  # let target know keep-alive is not supported

    create_task(WSTunClientProtocol.openTunnel((host.decode(), port), dat, reader, writer))


async def socks5_tcp_handler(dat: bytes, reader: StreamReader, writer: StreamWriter):
    # handle auth method selection
    dat += await reader.readexactly(dat[1])  # auth method count
    writer.write(b'\x05\x00')  # \x00 == NO AUTHENTICATION REQUIRED

    # handle relay request
    dat = await reader.readexactly(5)
    atyp = dat[3]
    # no "one send corresponds to one recv" assumption
    if atyp == 0x01:  # ipv4 4byte
        dat += await reader.readexactly(4 - 1 + 2)
    elif atyp == 0x03:  # domain
        dat += await reader.readexactly(dat[4] + 2)
    elif atyp == 0x04:  # ipv6 16byte
        dat += await reader.readexactly(16 - 1 + 2)

    try:
        cmd, addr_header = dat[1], dat[2:]
        target_addr, target_port = parse_socks5_addr(addr_header)
    except (ValueError, IndexError):
        logging.warning('invalid SOCKS v5 relay request')
        return writer.close()

    if cmd == 0x01:  # CONNECT
        # Initial Data:
        # Delay can be lowered (of a round-trip) by accepting request before connected to target.
        # But SOCKS client can't get real reason when error happens (not a big problem, Firefox always
        # display connection reset error). Dirty solution: generate a HTML page when a HTTP request failed
        # BND.ADDR and BND.PORT should be wstan server's outbound socket, so we have to return a fake value.
        writer.write(b'\x05\x00\x00\x01' + b'\x01' * 6)  # \x00 == SUCCEEDED
        try:
            init_dat = await wait_for(reader.read(INIT_DATA_LEN), INIT_DATA_TIMEOUT)
            if not init_dat:
                return writer.close()
        except asyncio.TimeoutError:
            # 20ms passed and no data received, rare but legal behavior.
            # timeout may always happen if set to 10ms, and enable asyncio library debug mode will "fix" it
            # e.g. Old SSH client will wait for server after conn established
            init_dat = None

        create_task(WSTunClientProtocol.openTunnel((target_addr, target_port), init_dat, reader, writer))
    elif cmd == 0x03:  # UDP ASSOCIATE
        # listen for udp packets
        tcp_socket = writer.get_extra_info('socket')  # udp should use same family as tcp socket
        udp_reader, udp_writer = await open_udp_endpoint((config.addr, 0), family=tcp_socket.family)
        udp_port = udp_writer.get_extra_info('socket').getsockname()[1]  # ephemeral port
        listen_addr = tcp_socket.getsockname()[0]  # exposed address which user-agent is talking to
        writer.write(b'\x05\x00' + make_socks5_addr(listen_addr, udp_port))  # \x00 == SUCCEEDED
        logging.debug('start listening udp port %s' % udp_port)

        # initial data, same as TCP. but must wait, because we need to know target address
        try:
            pkt = await wait_for(udp_reader.read(), 10)
        except asyncio.TimeoutError:
            logging.error('associate success but no udp packet received')
            udp_writer.close()
            return writer.close()
        if pkt is None:
            return writer.close()
        udp_writer.set_default_remote_addr(pkt.addr)
        target_addr, target_port, remain_idx = parse_sock5_udp_addr(pkt.data)

        create_task(WSTunClientProtocol.openTunnel((target_addr, target_port), pkt.data[remain_idx:], udp_reader, udp_writer))

        # user-agent will keep this connection open until finished sending udp packet
        try:
            await reader.read()
        finally:
            udp_writer.close()
            return writer.close()
    else:  # BIND
        writer.write(b'\x05\x07\x00\x01' + b'\x00' * 6)  # \x07 == COMMAND NOT SUPPORTED
        return writer.close()


async def socks4_tcp_handler(dat: bytes, reader: StreamReader, writer: StreamWriter):
    dat += await reader.readexactly(6)

    # Parse SOCKS v4 request
    try:
        cmd, port, ip = dat[1], dat[2:4], dat[4:8]
        if ip[:3] == b'\x00\x00\x00' and ip[3] != 0:  # SOCKS v4a (domain name)
            dat += await reader.readuntil(b'\x00')
            target_addr = dat[8:].decode('ascii')
        else:
            target_addr = socket.inet_ntoa(ip)
        target_port = int.from_bytes(port, 'big')
    except Exception:
        logging.warning('invalid SOCKS v4 request')
        return writer.close()

    # Only support CONNECT command
    if cmd != 0x01:  # CONNECT
        logging.warning('unsupported SOCKS v4 command')
        writer.write(b'\x00\x5B\x00\x00\x00\x00\x00\x00')  # \x5B == REQUEST_REJECTED
        return writer.close()

    # Send success response
    writer.write(b'\x00\x5A\x00\x00\x00\x00\x00\x00')  # \x5A == REQUEST_GRANTED

    # Read additional data if available
    try:
        dat = await wait_for(reader.read(INIT_DATA_LEN), INIT_DATA_TIMEOUT)
        if not dat:
            dat = None
    except asyncio.TimeoutError:
        dat = None

    create_task(WSTunClientProtocol.openTunnel((target_addr, target_port), dat, reader, writer))


async def setup_http_tunnel() -> socket.socket:
    sock = await my_sock_connect(config.proxy_host, config.proxy_port)
    pair = '%s:%d' % (config.uri_addr, config.uri_port)
    req = 'CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n' % (pair, pair)
    await loop.sock_sendall(sock, req.encode())
    dat = await loop.sock_recv(sock, 4096)
    while True:
        end = dat.find(b'\r\n\r\n')
        if end != -1:
            break
        r = await loop.sock_recv(sock, 4096)
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
        # real proxy may redirects or require authentication, not supported here
        if len(sl) > 2:
            reason = " - %s" % ''.join(sl[2:])
        else:
            reason = ""
        raise ConnectionError("HTTP proxy connect failed (%d%s)" % (status_code, reason))
    if dat[end+4:]:
        logging.warning('got extra data in HTTP proxy resp: %s' % dat[end+4:])

    return sock


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
    try:
        server = loop.run_until_complete(
            asyncio.start_server(dispatch_request, config.addr, config.port))
    except OSError:
        die('wstan client failed to bind on %s:%d' % (config.addr, config.port))

    print('wstan client -- SOCKS/HTTP server listening on %s:%d' % (config.addr, config.port))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        loop.close()
