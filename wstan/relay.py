import asyncio
import logging
import weakref
import hmac
import struct
import hashlib
import time
from autobahn.websocket.protocol import WebSocketProtocol
from wstan import config, parse_socks_addr
if config.key:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend


DIGEST_LEN = 20
TIMESTAMP_LEN = 8  # double


def _get_digest(dat):
    return hmac.new(config.key, dat, hashlib.sha1).digest()


class RelayMixin(WebSocketProtocol):
    # state of relay can be changed by methods resetTunnel & onResetTunnel
    # USING --RST-sent--> RESETTING --RST-received--> IDLE
    # USING --RST-received-and-RST-sent--> IDLE
    # IDLE --setProxy--> USING
    TUN_STATE_IDLE, TUN_STATE_USING, TUN_STATE_RESETTING = range(3)
    BUF_SIZE = 8192
    RELAY_REQ_TTL = 10  # in seconds
    allConn = weakref.WeakSet() if config.debug else None  # used to debug tunnel that never close

    def __init__(self):
        super().__init__()
        self.tunState = self.TUN_STATE_IDLE
        self._reader = None
        self._writer = None
        self._pushToTunTask = None
        self.cipher = self.encryptor = self.decryptor = None
        if config.debug:
            self.allConn.add(self)
            logging.debug('tunnel created (total %d)' % len(self.allConn))

    def parseRelayHeader(self, dat):
        """Extract addr, port and rest data from relay request."""
        originDat = dat
        if self.cipher:
            dat = dat[:DIGEST_LEN] + self.decryptor.update(dat[DIGEST_LEN:])
        addrIdx = DIGEST_LEN + TIMESTAMP_LEN
        digest, timestamp = dat[:DIGEST_LEN], dat[DIGEST_LEN:addrIdx]
        addrRest = dat[addrIdx:]
        addr, port, remainIdx = parse_socks_addr(addrRest, allow_remain=True)
        remain = addrRest[remainIdx:]  # remainIdx is relative to addrRest

        # If cipher is None then we are using SSL, and checking timestamp is meaning less.
        # But for simplicity this field still present.
        if self.cipher:
            try:
                t = struct.unpack('>d', timestamp)[0]
            except struct.error:
                raise ValueError('invalid timestamp')
            expire_time = t + self.RELAY_REQ_TTL
            if time.time() > expire_time:
                raise ValueError('request expired, req: %s, now: %s' % (t, time.time()))

        if len(digest) != DIGEST_LEN:
            raise ValueError('incorrect digest length')
        if not hmac.compare_digest(digest, _get_digest(originDat[DIGEST_LEN:addrIdx+remainIdx])):
            raise ValueError('authentication failed')
        return addr, port, remain

    def makeRelayHeader(self, addr_header, remain):
        """Construct relay request header.
        Format: hmac-sha1 of next 2 parts | timestamp | SOCKS address header | rest data
        If encryption enabled then timestamp and parts after it will be encrypted."""
        stampAddr = struct.pack('>d', time.time()) + addr_header
        if self.cipher:
            stampAddr = self.encryptor.update(stampAddr)
            remain = self.encryptor.update(remain)
        digest = _get_digest(stampAddr)
        return digest + stampAddr + remain

    def initCrypto(self, nonce):
        self.cipher = Cipher(algorithms.AES(config.key), modes.CTR(nonce), default_backend())
        self.encryptor, self.decryptor = self.cipher.encryptor(), self.cipher.decryptor()

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
            if self.cipher:
                dat = self.encryptor.update(dat)
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
