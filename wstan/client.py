import asyncio
import logging
import time
import os
import base64
from collections import deque
from autobahn.asyncio.websocket import WebSocketClientProtocol, WebSocketClientFactory
from wstan.relay import RelayMixin
from wstan import parse_relay_request, loop, config


# noinspection PyAttributeOutsideInit
class CustomWSClientProtocol(WebSocketClientProtocol):
    """Add auto-ping switch (dirty way) and let us manually start handshaking."""
    def __init__(self):
        super().__init__()
        self.customUriPath = '/'
        self.delayedHandshake = asyncio.Future()

    def enableAutoPing(self, interval):
        try:
            self.autoPingInterval = interval
            self.autoPingPendingCall = loop.call_later(interval, self._sendAutoPing)
        except AttributeError:
            logging.warning('failed to enable auto-ping, maybe library changed its internal method')

    def disableAutoPing(self):
        try:
            self.autoPingInterval = 0
            if self.autoPingPendingCall:
                self.autoPingPendingCall.cancel()
                self.autoPingPendingCall = None
        except AttributeError:
            logging.warning('failed to disable auto-ping')

    def startHandshake(self):
        """Delay handshake because some states must be set before handshake (so
        they can't be set in factory)."""
        self.delayedHandshake.set_result(None)

    def restartHandshake(self):
        """Customize handshake HTTP header."""
        asyncio.wait_for(self.delayedHandshake, 5)
        self.websocket_key = base64.b64encode(os.urandom(16))
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
        self.http_request_data = '\r\n'.join(request).encode('utf8')
        self.sendData(self.http_request_data)
        if self.debug:
            self.log.debug(request)


class WSTunClientProtocol(CustomWSClientProtocol, RelayMixin):
    POOL_MAX_SIZE = 16
    TUN_MAX_IDLE_TIMEOUT = 35  # in seconds. close tunnel on timeout
    TUN_PING_INTERVAL = 4  # only tunnels in pool do auto-ping
    POOL_NOM_SIZE, TUN_MIN_IDLE_TIMEOUT = round(POOL_MAX_SIZE / 2), round(TUN_MAX_IDLE_TIMEOUT / 2)
    pool = deque()

    def __init__(self):
        super().__init__()
        self.lastIdleTime = None
        self.checkTimeoutTask = None
        self.tunOpen = asyncio.Future()
        self.pool = None

    if TUN_MAX_IDLE_TIMEOUT <= 0:
        def resetTunnel(self):
            self.sendClose(1000, reason='tunnel keep-alive disabled')

        def onResetTunnel(self):
            self.sendClose(1000, reason='tunnel keep-alive disabled')

    def _clearProxy(self):
        super()._clearProxy()
        self.lastIdleTime = time.time()
        WSTunClientProtocol.addToPool(self)

    def onOpen(self):
        self.tunOpen.set_result(None)
        self.lastIdleTime = time.time()

    def onMessage(self, payload, isBinary):
        if not isBinary:
            assert payload == b'RST'
            self.onResetTunnel()
            return

        if self.tunState == self.TUN_STATE_RESETTING1:
            return

        if self._writer:
            self._writer.write(payload)

    def onClose(self, *args, **kwargs):
        super().onClose(*args, **kwargs)
        if self.pool:
            self.pool.remove(self)
            self.pool = None

    @classmethod
    @asyncio.coroutine
    def _checkTimeout(cls, tun):
        while tun.state == cls.STATE_OPEN:
            timeout = (cls.TUN_MAX_IDLE_TIMEOUT if len(cls.pool) <= cls.POOL_NOM_SIZE else
                       cls.TUN_MIN_IDLE_TIMEOUT)
            yield from asyncio.sleep(timeout)
            if (tun.tunState == cls.TUN_STATE_IDLE and
               (time.time() - tun.lastIdleTime) > timeout):
                tun.sendClose(1000, reason='tunnel idle timeout')

    @classmethod
    def addToPool(cls, tun):
        assert tun.tunState == cls.TUN_STATE_IDLE
        if len(cls.pool) >= cls.POOL_MAX_SIZE:
            tun.sendClose(1000, reason='pool is full')
        else:
            assert not tun.checkTimeoutTask
            tun.checkTimeoutTask = asyncio.async(cls._checkTimeout(tun))
            tun.pool = cls.pool
            tun.enableAutoPing(cls.TUN_PING_INTERVAL)
            cls.pool.append(tun)

    @classmethod
    @asyncio.coroutine
    def getOrCreate(cls, initData):
        if WSTunClientProtocol.pool:
            logging.debug('reuse tunnel from pool (total %s)' % len(WSTunClientProtocol.pool))
            tun = WSTunClientProtocol.pool.popleft()
            tun.checkTimeoutTask.cancel()
            tun.checkTimeoutTask = None
            tun.pool = None
            tun.disableAutoPing()
            tun.sendMessage(initData, isBinary=True)
        else:
            tun = (yield from loop.create_connection(
                factory, config.uri_addr, config.uri_port, ssl=config.tun_ssl))[1]
            # lower latency by sending relay header and data in ws handshake
            tun.customUriPath = '/' + base64.b64encode(initData).decode()
            tun.restartHandshake()
            try:
                yield from asyncio.wait_for(tun.tunOpen, 5)
            except asyncio.TimeoutError:
                tun.dropConnection()
                raise
        return tun


factory = WebSocketClientFactory(config.uri)
factory.protocol = WSTunClientProtocol
factory.useragent = ''
factory.autoPingTimeout = 3


@asyncio.coroutine
def socks5_tcp_handler(reader, writer):
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
        cmd, target_info = dat[1], dat[2:]
        target_addr, target_port = parse_relay_request(target_info, allow_remain=False)
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

    try:
        tun = yield from WSTunClientProtocol.getOrCreate(target_info + dat)
    except Exception as e:
        logging.error('failed to establish tunnel: %s' % e)
        return writer.close()
    tun.setProxy(reader, writer)


def main():
    server = loop.run_until_complete(
        asyncio.start_server(socks5_tcp_handler, config.addr, config.port))
    print('wstan client -- SOCKS v5 server listen on %s:%d' % (config.addr, config.port))
    try:
        loop.run_forever()
    finally:
        server.close()
        loop.close()
