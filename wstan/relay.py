import asyncio
import logging
import weakref
from autobahn.websocket.protocol import WebSocketProtocol
from wstan import config


class RelayMixin(WebSocketProtocol):
    # state of relay can be changed by methods resetTunnel & onResetTunnel
    # USING --RST-sent--> RESETTING --RST-received--> IDLE
    # USING --RST-received-and-RST-sent--> IDLE
    # IDLE --setProxy--> USING
    TUN_STATE_IDLE, TUN_STATE_USING, TUN_STATE_RESETTING = range(3)
    BUF_SIZE = 8192
    allConn = weakref.WeakSet() if config.debug else None  # used to debug tunnel that never close

    def __init__(self):
        super().__init__()
        self.tunState = self.TUN_STATE_IDLE
        self._reader = None
        self._writer = None
        self._pushToTunTask = None
        if config.debug:
            self.allConn.add(self)
            logging.debug('tunnel created (total %d)' % len(self.allConn))

    def setProxy(self, reader, writer):
        self.tunState = self.TUN_STATE_USING
        self._reader, self._writer = reader, writer
        self._pushToTunTask = asyncio.async(self._pushToTunnelLoop())

    def succeedReset(self):
        """This method will be called after succeeded to reset tunnel."""
        logging.debug('reset tunnel succeed')
        self._writer = self._reader = self._pushToTunTask = None
        self.tunState = self.TUN_STATE_IDLE

    @asyncio.coroutine
    def _pushToTunnelLoop(self):
        while True:
            try:
                dat = yield from self._reader.read(self.BUF_SIZE)
            except ConnectionError:
                return self.sendClose(3006, reason='connection to target broken')
            if not dat:
                return self.resetTunnel()
            self.sendMessage(dat, isBinary=True)

    def resetTunnel(self):
        if self.tunState == self.TUN_STATE_USING:
            self.sendMessage(b'RST')
            self._pushToTunTask.cancel()
            self._writer.close()
            self.tunState = self.TUN_STATE_RESETTING
        else:
            self.sendClose(3001, reason='tried to reset from %d' % self.tunState)

    def onResetTunnel(self):
        if self.tunState == self.TUN_STATE_USING:
            self.sendMessage(b'RST')
            self._pushToTunTask.cancel()
            self._writer.close()
            self.succeedReset()
        elif self.tunState == self.TUN_STATE_RESETTING:
            self.tunState = self.TUN_STATE_IDLE
            self.succeedReset()
        else:
            self.sendClose(3001, reason='tried to reset on %d' % self.tunState)

    def onClose(self, wasClean, code, reason):
        if not wasClean or code != 1000:
            if self._writer:
                self._writer.close()
            if self._pushToTunTask:
                self._pushToTunTask.cancel()
            logging.warning('relay broken: %s' % (reason or code))
        if config.debug:
            self.allConn.remove(self)
            logging.debug('tunnel closed (total %d)' % len(self.allConn))
