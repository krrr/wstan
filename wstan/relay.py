# Copyright (c) 2020 krrr
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
import logging
import weakref
import hmac
import struct
import hashlib
import time
import random
from asyncio import ensure_future, Future, CancelledError
from asyncio.streams import FlowControlMixin, StreamReader, StreamWriter
from wstan import config, parse_socks5_addr, make_socks_addr
if not config.tun_ssl:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend


DIGEST_LEN = 10
TIMESTAMP_LEN = 8  # double


def _get_digest(dat):
    return hmac.new(config.key, dat, hashlib.sha1).digest()[:DIGEST_LEN]


def _on_pushToTunTaskDone(task):
    # suppress annoying "CancelledError exception not retrieved" error on Py3.5+
    try:
        task.exception()
    except CancelledError:  # doc says it will raise this if canceled, but...
        pass


class OurFlowControlMixin(FlowControlMixin):
    async def drain(self):
        """Wait for all queued messages to be sent."""
        await self._drain_helper()


class RelayMixin(OurFlowControlMixin):
    # states of relay:
    # --> IDLE (initial)
    # USING --RST-sent--> RESETTING --RST-received--> IDLE
    # USING --RST-received-and-RST-sent--> IDLE
    # IDLE --setProxy--> USING
    TUN_STATE_IDLE, TUN_STATE_USING, TUN_STATE_RESETTING = range(3)
    BUF_SIZE = random.randrange(4096, 8192)
    REQ_TTL = 60  # in seconds
    CMD_REQ, CMD_DAT, CMD_RST = range(3)  # every ws message has this command type
    DAT_LOG_MAX_LEN = 60  # maximum length of logged data which triggered error, in bytes
    PUSH_TO_TUN_CONN_ERR_MSG = 'override me!'
    allConn = weakref.WeakSet() if config.debug else None  # used to debug resource leak

    def __init__(self):
        OurFlowControlMixin.__init__(self)
        self.tunState = self.TUN_STATE_IDLE
        self.tunOpen = Future()  # connected and authenticated
        self._reader = None
        self._writer = None
        self._pushToTunTask = None
        # they do nothing if websocket is not wrapped in SSL
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

        addr, port, remainIdx = parse_socks5_addr(dat[TIMESTAMP_LEN:], allow_remain=True)
        remain = dat[TIMESTAMP_LEN+remainIdx:]  # remainIdx is relative to addrRest

        # If we are using SSL then checking timestamp is meaningless.
        # But for simplicity this field still present.
        stamp = None
        if not config.tun_ssl:
            try:
                stamp = struct.unpack('>d', dat[:TIMESTAMP_LEN])[0]
            except struct.error:
                raise ValueError('invalid timestamp')
            if abs(time.time() - stamp) > self.REQ_TTL:
                raise ValueError('request expired (%.1fs old), decrypted dat: %s' %
                                 (time.time() - stamp, dat[:self.DAT_LOG_MAX_LEN]))

        return addr, port, remain, stamp

    def makeRelayHeader(self, target: (str, int), remain_data: bytes):
        """Construct relay request header.
        Format: CMD_REQ | timestamp | SOCKS address header | rest data | hmac-sha1 of previous parts
        If encryption enabled then timestamp and parts after it will be encrypted."""
        addr_header = make_socks_addr(target[0].encode(), target[1])
        dat = struct.pack('>Bd', self.CMD_REQ, time.time()) + addr_header + (remain_data or b'')
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

    def setProxy(self, reader: StreamReader, writer: StreamWriter, startPushLoop=True):
        self.tunState = self.TUN_STATE_USING
        self._reader, self._writer = reader, writer
        if startPushLoop:
            self.startPushToTunLoop()

    def succeedReset(self):
        """This method will be called after succeeded to reset tunnel."""
        logging.debug('tunnel reset succeed')
        self._writer = self._reader = self._pushToTunTask = None
        self.tunState = self.TUN_STATE_IDLE

    async def _pushToTunnelLoop(self):
        while True:
            try:
                dat = await self._reader.read(self.BUF_SIZE)
            except ConnectionError:
                return self.resetTunnel(self.PUSH_TO_TUN_CONN_ERR_MSG)
            if not dat:
                return self.resetTunnel()
            dat = bytes([self.CMD_DAT]) + dat
            self.sendMessage(self.encrypt(dat), True)
            await self.drain()

    def startPushToTunLoop(self):
        assert not self._pushToTunTask
        self._pushToTunTask = ensure_future(self._pushToTunnelLoop())
        self._pushToTunTask.add_done_callback(_on_pushToTunTaskDone)

    def _makeResetMessage(self, reason='', err=''):
        dat = self.encrypt(bytes([self.CMD_RST]) + (reason+'★'+err).encode('utf-8') +
                           b' ' * random.randrange(40, 500))
        return dat + _get_digest(dat)

    def parseResetMessage(self, dat):
        digest = dat[-DIGEST_LEN:]
        if len(digest) != DIGEST_LEN:
            raise ValueError('incorrect digest length')
        if not hmac.compare_digest(digest, _get_digest(dat[:-DIGEST_LEN])):
            raise ValueError('authentication failed')
        ret = self.decrypt(dat[1:-DIGEST_LEN]).rstrip().decode('utf-8').split('★')
        return (ret[0], '') if len(ret) == 1 else ret  # for old version wstan server

    def resetTunnel(self, reason=''):
        if self.tunState == self.TUN_STATE_USING:
            logging.debug('resetting tunnel')
            self.sendMessage(self._makeResetMessage(reason), True)
            self._pushToTunTask.cancel()
            self._writer.close()
            self.tunState = self.TUN_STATE_RESETTING
        else:
            self.sendClose(3001)
            logging.error('wrong state in resetTunnel: %s' % self.tunState)

    def onResetTunnel(self):
        if self.tunState == self.TUN_STATE_USING:
            self.sendMessage(self._makeResetMessage(), True)
            self._pushToTunTask.cancel()
            self._writer.close()
            self.succeedReset()
        elif self.tunState == self.TUN_STATE_RESETTING:
            self.succeedReset()
        else:
            self.sendClose(3001)
            logging.error('wrong state in onResetTunnel: %s' % self.tunState)

    def onClose(self, wasClean, code, reason, logWarn=True):
        if self._writer:
            self._writer.close()
        if self._pushToTunTask:
            self._pushToTunTask.cancel()
        if logWarn and not wasClean and reason:
            logging.warning('tunnel broken: ' + reason)
        if config.debug:
            self.allConn.remove(self)
            logging.debug('tunnel closed (total %d)' % len(self.allConn))
