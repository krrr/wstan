import asyncio
import logging
import time
from collections import deque
from autobahn.asyncio.websocket import WebSocketClientProtocol, WebSocketClientFactory
from wstan.relay import RelayMixin
from wstan import parse_relay_request, loop, config


# noinspection PyAttributeOutsideInit
class CustomWSClientProtocol(WebSocketClientProtocol):
    """Add auto-ping switch (dirty way)."""
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


class WSTunClientProtocol(CustomWSClientProtocol, RelayMixin):
    POOL_MAX_SIZE = 16
    TUN_MAX_IDLE_TIMEOUT = 35  # in seconds. close tunnel on timeout
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
            tun.enableAutoPing(4)
            cls.pool.append(tun)

    @classmethod
    @asyncio.coroutine
    def getOrCreate(cls):
        if WSTunClientProtocol.pool:
            logging.debug('reuse tunnel from pool (total %s)' % len(WSTunClientProtocol.pool))
            tun = WSTunClientProtocol.pool.popleft()
            tun.checkTimeoutTask.cancel()
            tun.checkTimeoutTask = None
            tun.pool = None
            tun.disableAutoPing()
        else:
            tun = (yield from loop.create_connection(
                factory, config.uri_addr, config.uri_port, ssl=config.tun_ssl))[1]
            yield from asyncio.wait([tun.tunOpen], timeout=5)
        return tun


factory = WebSocketClientFactory(config.uri)
factory.protocol = WSTunClientProtocol
factory.useragent = ''
factory.autoPingTimeout = 3


@asyncio.coroutine
def tcp_proxy_req_handler(reader, writer):
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
        cmd, target_info = dat[1], dat[3:]
        target_addr, target_port = parse_relay_request(target_info, allow_remain=False)
    except (ValueError, IndexError):
        logging.warning('invalid SOCKS v5 relay request')
        return writer.close()
    logging.info('requested %s:%d' % (target_addr, target_port))
    if cmd != 0x01:  # CONNECT
        writer.write(b'\x05\x07\x00\x01' + b'\x00' * 6)  # \x07 == COMMAND NOT SUPPORTED
        return writer.close()

    # By accepting request before connected to target delay can be lowered (of a round-trip).
    # But SOCKS client can't get real reason when error happens (Firefox always display
    # connection reset error). Dirty solution: generate a HTML page when a HTTP request failed
    writer.write(b'\x05\x00\x00\x01' + b'\x01' * 6)  # \x00 == SUCCEEDED
    try:
        dat = yield from reader.read(WSTunClientProtocol.BUF_SIZE)
    except ConnectionError:
        dat = None
    if not dat:
        return writer.close()

    try:
        tun = yield from WSTunClientProtocol.getOrCreate()
    except (ConnectionError, OSError, TimeoutError, asyncio.TimeoutError) as e:
        logging.error('failed to establish tunnel: %s' % e)
        return writer.close()

    tun.sendMessage(target_info + dat, isBinary=True)
    tun.setProxy(reader, writer)


def main():
    server = loop.run_until_complete(
        asyncio.start_server(tcp_proxy_req_handler, config.addr, config.port))
    print('wstan client -- SOCKS v5 server listen on %s:%d' % (config.addr, config.port))
    try:
        loop.run_forever()
    finally:
        server.close()
        loop.close()
