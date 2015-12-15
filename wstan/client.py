import asyncio
import logging
import time
import os
import base64
from collections import deque
from wstan.autobahn.asyncio.websocket import WebSocketClientProtocol, WebSocketClientFactory
from wstan.relay import RelayMixin
from wstan import (parse_socks_addr, loop, config, can_return_error_page,
                   gen_error_page, get_sha1)


# noinspection PyAttributeOutsideInit
class CustomWSClientProtocol(WebSocketClientProtocol):
    """Add auto-ping switch (dirty way) and let us manually start handshaking."""
    # this framework mix camel and underline naming style, nice!
    def __init__(self):
        super().__init__()
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
        """Delay handshake because some states must be set before handshake (so
        they can't be set in factory)."""
        self.delayedHandshake.set_result(None)

    def restartHandshake(self):
        """Customize handshake HTTP header."""
        asyncio.wait_for(self.delayedHandshake, None)
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
    TUN_MAX_IDLE_TIMEOUT = 35  # in seconds. close tunnel on timeout
    TUN_PING_INTERVAL = 5  # only tunnels in pool do auto-ping
    TUN_OPEN_TIMEOUT = 5  # time to wait after TCP established and before succeeded WS handshake
    POOL_NOM_SIZE, TUN_MIN_IDLE_TIMEOUT = round(POOL_MAX_SIZE / 2), round(TUN_MAX_IDLE_TIMEOUT / 2)
    pool = deque()

    def __init__(self):
        super().__init__()
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
                    self._writer.write(gen_error_page("can't connect to destination", msg))
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

    def onClose(self, *args, **kwargs):
        super().onClose(*args, **kwargs)
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
    def getOrCreate(cls, addrHeader, dat):
        if WSTunClientProtocol.pool:
            logging.debug('reuse tunnel from pool (total %s)' % len(WSTunClientProtocol.pool))
            tun = WSTunClientProtocol.pool.popleft()
            tun.checkTimeoutTask.cancel()
            tun.checkTimeoutTask = None
            tun.inPool = False
            tun.disableAutoPing()
            tun.sendMessage(tun.makeRelayHeader(addrHeader, dat), True)
        else:
            tun = (yield from loop.create_connection(
                factory, config.uri_addr, config.uri_port, ssl=config.tun_ssl))[1]
            # lower latency by sending relay header and data in ws handshake
            tun.customUriPath = '/' + base64.urlsafe_b64encode(tun.makeRelayHeader(addrHeader, dat)).decode()
            tun.restartHandshake()
            try:
                yield from asyncio.wait_for(tun.tunOpen, cls.TUN_OPEN_TIMEOUT)
            except asyncio.TimeoutError:
                tun.dropConnection()
                raise ConnectionRefusedError(tun.wasNotCleanReason)
        return tun


factory = WebSocketClientFactory(config.uri)
factory.protocol = WSTunClientProtocol
factory.useragent = ''
factory.autoPingTimeout = 5
factory.openHandshakeTimeout = 10


@asyncio.coroutine
def socks5_tcp_handler(reader, writer):
    # these codes assume one send cause one recv, because SOCKS server is at localhost

    # handle auth method selection
    dat = yield from reader.read(257)
    if len(dat) < 2 or dat[0] != 0x05 or len(dat) != dat[1] + 2:
        logging.warning('local SOCKS v5 server got unknown request')
        return writer.close()
    writer.write(b'\x05\x00')  # \x00 == NO AUTHENTICATION REQUIRED

    # handle relay request
    try:
        dat = yield from reader.read(262)
    except ConnectionError:
        return writer.close()
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
    try:
        dat = yield from reader.read(2048)
    except ConnectionError:
        dat = None
    if not dat:
        return writer.close()

    canErr = can_return_error_page(dat)
    try:
        tun = yield from WSTunClientProtocol.getOrCreate(addr_header, dat)
    except Exception as e:
        logging.error("can't connect to server: %s" % e)
        if canErr:
            writer.write(gen_error_page("can't connect to wstan server", str(e)))
        return writer.close()
    tun.canReturnErrorPage = canErr
    tun.setProxy(reader, writer)


def main():
    server = loop.run_until_complete(
        asyncio.start_server(socks5_tcp_handler, 'localhost', config.port))
    print('wstan client -- SOCKS v5 server listen on localhost:%d' % config.port)
    try:
        loop.run_forever()
    finally:
        server.close()
        loop.close()
