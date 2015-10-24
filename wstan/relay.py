import asyncio
import logging
import weakref
from autobahn.websocket.protocol import WebSocketProtocol
from wstan import config


class RelayMixin(WebSocketProtocol):
    # state of relay can be changed by methods resetTunnel & onResetTunnel
    # USING --RST-sent--> RESETTING2 --RST-received--> IDLE
    # USING --RST-received--> RESETTING1 --RST-sent--> IDLE
    # IDLE --setProxy--> USING
    # IDLE --RST-received--> IDLE
    # IDLE --RST-sent--> IDLE  (when failed to connect target)
    # relay on RESETTING1 can still push data to tunnel, and pull data from tunnel on RESETTING2
    TUN_STATE_IDLE, TUN_STATE_USING, TUN_STATE_RESETTING1, TUN_STATE_RESETTING2 = range(4)
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

    def _clearProxy(self):
        # this will be called after tunnel reset
        self._writer = self._reader = self._pushToTunTask = None
        self.tunState = self.TUN_STATE_IDLE
        logging.debug('reset tunnel succeed')

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
            self._reader = self._pushToTunTask = None
            self.tunState = self.TUN_STATE_RESETTING2
        elif self.tunState == self.TUN_STATE_RESETTING1:
            self.sendMessage(b'RST')
            self._clearProxy()
        elif self.tunState == self.TUN_STATE_IDLE:
            self.sendMessage(b'RST')
        else:
            self.sendClose(3001, reason='tried to reset from %d' % self.tunState)

    def onResetTunnel(self):
        if self.tunState == self.TUN_STATE_USING:
            self._writer.close()
            self._writer = None
            self.tunState = self.TUN_STATE_RESETTING1
        elif self.tunState == self.TUN_STATE_RESETTING2:
            self.sendMessage(b'RST')
            self._clearProxy()
        elif self.tunState == self.TUN_STATE_IDLE:
            pass
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
