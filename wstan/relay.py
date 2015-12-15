import asyncio
import logging
import weakref
import hmac
import struct
import hashlib
import time
import random
from asyncio.streams import FlowControlMixin
from wstan.autobahn.websocket.protocol import WebSocketProtocol
from wstan import config, parse_socks_addr
if not config.tun_ssl:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend


DIGEST_LEN = 10
TIMESTAMP_LEN = 8  # double


def _get_digest(dat):
    return hmac.new(config.key, dat, hashlib.sha1).digest()[:DIGEST_LEN]


class FlowControlledWSProtocol(FlowControlMixin, WebSocketProtocol):
    def __init__(self):
        FlowControlMixin.__init__(self)
        WebSocketProtocol.__init__(self)

    @asyncio.coroutine
    def drain(self):
        """Wait for all queued messages to be sent."""
        yield from self._drain_helper()


class RelayMixin(FlowControlledWSProtocol):
    # states of relay:
    # --> IDLE (initial)
    # USING --RST-sent--> RESETTING --RST-received--> IDLE
    # USING --RST-received-and-RST-sent--> IDLE
    # IDLE --setProxy--> USING
    TUN_STATE_IDLE, TUN_STATE_USING, TUN_STATE_RESETTING = range(3)
    BUF_SIZE = random.randrange(4096, 8192)
    REQ_TTL = 15  # in seconds
    CMD_REQ, CMD_DAT, CMD_RST = range(3)  # every ws message has this command type
    DAT_LOG_MAX_LEN = 270  # maximum length of logged data which triggered error, in bytes
    allConn = weakref.WeakSet() if config.debug else None  # used to debug resource leak

    def __init__(self):
        super().__init__()
        self.tunState = self.TUN_STATE_IDLE
        self._reader = None
        self._writer = None
        self._pushToTunTask = None
        # they do nothing if if websocket is not wrapped in SSL
        self.encrypt = self.decrypt = lambda dat: dat
        if config.debug:
            self.allConn.add(self)
            logging.debug('tunnel created (total %d)' % len(self.allConn))

    def parseRelayHeader(self, dat):
        """Extract addr, port and rest data from relay request. Parts except CMD (first byte)
        and HMAC (not encrypted) will be decrypted if encryption enabled. CMD should be
        raw but checked before calling this function."""
        digest = dat[-DIGEST_LEN:]
        err = ''
        if len(digest) != DIGEST_LEN:
            err = 'incorrect digest length'
        if not hmac.compare_digest(digest, _get_digest(dat[:-DIGEST_LEN])):
            err = 'authentication failed'

        dat = self.decrypt(dat[1:-DIGEST_LEN])
        if err:
            raise ValueError(err + ', decrypted dat: %s' % dat[:self.DAT_LOG_MAX_LEN])

        addr, port, remainIdx = parse_socks_addr(dat[TIMESTAMP_LEN:], allow_remain=True)
        remain = dat[TIMESTAMP_LEN+remainIdx:]  # remainIdx is relative to addrRest

        # If we are using SSL then checking timestamp is meaningless.
        # But for simplicity this field still present.
        if not config.tun_ssl:
            try:
                t = struct.unpack('>d', dat[:TIMESTAMP_LEN])[0]
            except struct.error:
                raise ValueError('invalid timestamp')
            expire_time = t + self.REQ_TTL
            if time.time() > expire_time:
                raise ValueError('request expired (%.1fs old), decrypted dat: %s' %
                                 (time.time() - t, dat))

        return addr, port, remain

    def makeRelayHeader(self, addr_header, remain):
        """Construct relay request header.
        Format: CMD_REQ | timestamp | SOCKS address header | rest data | hmac-sha1 of previous parts
        If encryption enabled then timestamp and parts after it will be encrypted."""
        dat = struct.pack('>Bd', self.CMD_REQ, time.time()) + addr_header + remain
        dat = self.encrypt(dat)
        return dat + _get_digest(dat)

    def initCipher(self, nonce, encryptor=False, decryptor=False):
        assert not (encryptor and decryptor)
        cipher = Cipher(algorithms.AES(config.key), modes.CTR(nonce), default_backend())
        if encryptor:
            enc = cipher.encryptor()
            self.encrypt = lambda dat: enc.update(dat)
        elif decryptor:
            dec = cipher.decryptor()
            self.decrypt = lambda dat: dec.update(dat)

    def setProxy(self, reader, writer):
        self.tunState = self.TUN_STATE_USING
        self._reader, self._writer = reader, writer
        self._pushToTunTask = asyncio.async(self._pushToTunnelLoop())

    def succeedReset(self):
        """This method will be called after succeeded to reset tunnel."""
        logging.debug('tunnel reset succeed')
        self._writer = self._reader = self._pushToTunTask = None
        self.tunState = self.TUN_STATE_IDLE

    @asyncio.coroutine
    def _pushToTunnelLoop(self):
        while True:
            try:
                dat = yield from self._reader.read(self.BUF_SIZE)
            except ConnectionError:
                # this may also happen in wstan client, but rare, so assume it's in server
                return self.resetTunnel('connection to target broken')
            if not dat:
                return self.resetTunnel()
            dat = bytes([self.CMD_DAT]) + dat
            self.sendMessage(self.encrypt(dat), True)
            yield from self.drain()

    def makeResetMessage(self, reason=''):
        dat = bytes([self.CMD_RST]) + (reason or ' ' * random.randrange(2, 8)).encode('utf-8')
        dat = self.encrypt(dat)
        return dat + _get_digest(dat)

    def parseResetMessage(self, dat):
        digest = dat[-DIGEST_LEN:]
        if len(digest) != DIGEST_LEN:
            raise ValueError('incorrect digest length')
        if not hmac.compare_digest(digest, _get_digest(dat[:-DIGEST_LEN])):
            raise ValueError('authentication failed')
        return self.decrypt(dat[1:-DIGEST_LEN]).decode('utf-8')

    def resetTunnel(self, reason=''):
        if self.tunState == self.TUN_STATE_USING:
            self.sendMessage(self.makeResetMessage(reason), True)
            self._pushToTunTask.cancel()
            self._writer.close()
            self.tunState = self.TUN_STATE_RESETTING
        else:
            self.sendClose(3001)

    def onResetTunnel(self):
        if self.tunState == self.TUN_STATE_USING:
            self.sendMessage(self.makeResetMessage(), True)
            self._pushToTunTask.cancel()
            self._writer.close()
            self.succeedReset()
        elif self.tunState == self.TUN_STATE_RESETTING:
            self.succeedReset()
        else:
            self.sendClose(3001)

    def onClose(self, wasClean, code, reason):
        if not wasClean or code != 1000:
            if self._writer:
                self._writer.close()
            if self._pushToTunTask:
                self._pushToTunTask.cancel()
            desc = ': %s' % (reason or code or 'unknown reason') if config.debug else ''
            logging.warning('tunnel broken' + desc)
        if config.debug:
            self.allConn.remove(self)
            logging.debug('tunnel closed (total %d)' % len(self.allConn))
