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
import weakref
import hmac
import struct
import hashlib
import time
import random
from asyncio import ensure_future, Future, CancelledError
from asyncio.streams import FlowControlMixin, StreamReader, StreamWriter
from wstan import config, parse_socks5_addr, make_socks5_addr, parse_sock5_udp_addr
from wstan.utils import UdpEndpointClosedError, UdpReader, UdpWriter
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

DIGEST_LEN = 10
TIMESTAMP_LEN = 8  # double


def _get_digest(dat):
    return hmac.new(config.bin_key, dat, hashlib.sha1).digest()[:DIGEST_LEN]


# def _on_pushToTunTaskDone(task):
#     # suppress annoying "CancelledError exception not retrieved" error on Py3.5+
#     try:
#         task.exception()
#     except CancelledError:  # doc says it will raise this if canceled, but...
#         pass


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
    CMD_REQ, CMD_DAT, CMD_RST, CMD_DGM = range(4)  # every ws message has this command type
    DAT_LOG_MAX_LEN = 60  # maximum length of logged data which triggered error, in bytes
    PUSH_TO_TUN_CONN_ERR_MSG = 'override me!'
    allConn = weakref.WeakSet() if config.debug else None  # used to debug resource leak

    def __init__(self):
        OurFlowControlMixin.__init__(self)
        self.tunState = self.TUN_STATE_IDLE
        self.tunOpen = Future()  # connected and authenticated
        self._pushToTunTasks = []
        self._exclusiveReader = None  # for client, it's udp or tcp. for server, it's only tcp
        self._exclusiveWriter = None
        # they do nothing if websocket is not wrapped in SSL
        self.encrypt = self.decrypt = lambda dat: dat
        if config.debug:
            self.allConn.add(self)
            logging.debug('tunnel created (total %d)' % len(self.allConn))

    def parseRelayHeader(self, dat: bytes):
        """Extract addr, port and rest data from relay request. Parts except CMD (first byte)
        and HMAC (not encrypted) will be decrypted if encryption enabled. CMD should be
        raw but checked before calling this function."""
        decrypted, stamp = self._decryptVerifyRelayHeader(dat, not config.tun_ssl)
        addr, port, remain_idx = parse_socks5_addr(decrypted, True)
        return addr, port, decrypted[remain_idx:], stamp

    def parseEmptyHeader(self, dat: bytes):
        """Return single timestamp."""
        return self._decryptVerifyRelayHeader(dat, not config.tun_ssl)[1]

    def _decryptVerifyRelayHeader(self, dat: bytes, checkTimestamp: bool):
        """Verify relay header digest and check timestamp (optional)"""
        digest = dat[-DIGEST_LEN:]
        err = ''
        if len(digest) != DIGEST_LEN:
            err = 'incorrect digest length'
        if not hmac.compare_digest(digest, _get_digest(dat[:-DIGEST_LEN])):
            err = 'authentication failed'

        dat = self.decrypt(dat[1:-DIGEST_LEN])
        if err:
            raise ValueError(err + ', decrypted dat: %s' % dat[:self.DAT_LOG_MAX_LEN])

        # If we are using SSL then checking timestamp is meaningless.
        # But for simplicity this field still present.
        stamp = None
        if checkTimestamp:
            try:
                stamp = struct.unpack('>d', dat[:TIMESTAMP_LEN])[0]
            except struct.error:
                raise ValueError('invalid timestamp')
            if abs(time.time() - stamp) > self.REQ_TTL:
                raise ValueError('request expired (%.1fs old), decrypted dat: %s' %
                                 (time.time() - stamp, dat[:self.DAT_LOG_MAX_LEN]))

        return dat[TIMESTAMP_LEN:], stamp

    def makeRelayHeader(self, target: (str, int), init_data: bytes, is_udp=False):
        """Construct relay request header.
        Format: CMD_REQ or CMD_DGM | timestamp | SOCKS address header | rest data | hmac-sha1 of previous parts
        If encryption enabled then timestamp and parts after it will be encrypted."""
        addr_header = make_socks5_addr(target[0], target[1])
        dat = struct.pack('>Bd', self.CMD_DGM if is_udp else self.CMD_REQ, time.time()) + addr_header + (init_data or b'')
        dat = self.encrypt(dat)
        return dat + _get_digest(dat)

    # for future use
    # def makeEmptyHeader(self):
    #     """Construct emtpy header. Used to establish channel and enter IDLE state immediately.
    #     Format: CMD_RST | timestamp | hmac-sha1 of previous parts"""
    #     dat = struct.pack('>Bd', self.CMD_RST, time.time())
    #     dat = self.encrypt(dat)
    #     return dat + _get_digest(dat)

    def makeDatagramMessage(self, target: (str, int), data: bytes):
        """Format: CMD_DGM | SOCKS address header | UDP package data"""
        return self.encrypt(bytes([self.CMD_DGM]) + make_socks5_addr(*target) + data)

    def initCipher(self, nonce, encryptor=False, decryptor=False):
        assert not (encryptor and decryptor)
        cipher = Cipher(algorithms.AES(config.bin_key), modes.CTR(nonce), default_backend())
        if encryptor:
            enc = cipher.encryptor()
            self.encrypt = lambda dat: enc.update(dat)
        elif decryptor:
            dec = cipher.decryptor()
            self.decrypt = lambda dat: dec.update(dat)

    def setProxy(self, reader: StreamReader | UdpReader, writer: StreamWriter | UdpWriter, startPushLoop=True):
        self.tunState = self.TUN_STATE_USING
        if startPushLoop:
            self.startPushToTunLoop(reader, writer)

    def succeedReset(self):
        """This method will be called after succeeded to reset tunnel."""
        logging.debug('tunnel reset succeed')
        self.tunState = self.TUN_STATE_IDLE

    async def _pushToTunnelLoopTcp(self, reader: StreamReader, writer: StreamWriter):
        while True:
            try:
                dat = await reader.read(self.BUF_SIZE)
            except asyncio.CancelledError:
                break
            except ConnectionError:
                self.resetTunnel(self.PUSH_TO_TUN_CONN_ERR_MSG)
                break
            if not dat:
                self.resetTunnel()
                break
            dat = bytes([self.CMD_DAT]) + dat
            self.sendMessage(self.encrypt(dat), True)
            await self.drain()

        writer.close()

    async def _pushToTunnelLoopUdp(self, reader: UdpReader, writer: UdpWriter):
        """UDP version of _pushToTunnelLoop. Logic is different in server and client."""
        raise NotImplementedError

    def startPushToTunLoop(self, reader: StreamReader | UdpReader, writer: StreamWriter | UdpWriter):
        if isinstance(reader, UdpReader):
            task = asyncio.create_task(self._pushToTunnelLoopUdp(reader, writer))
        else:
            assert isinstance(reader, StreamReader)
            assert not len(self._pushToTunTasks)
            task = asyncio.create_task(self._pushToTunnelLoopTcp(reader, writer))
        # task.add_done_callback(_on_pushToTunTaskDone)
        self._pushToTunTasks.append(task)

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
            self._closeAllPushToTun()
            self.tunState = self.TUN_STATE_RESETTING
        else:
            self.sendClose(3001)
            logging.error('wrong state in resetTunnel: %s' % self.tunState)

    def onResetTunnel(self):
        if self.tunState == self.TUN_STATE_USING:
            self.sendMessage(self._makeResetMessage(), True)
            self._closeAllPushToTun()
            self.succeedReset()
        elif self.tunState == self.TUN_STATE_RESETTING:
            self.succeedReset()
        else:
            self.sendClose(3001)
            logging.error('wrong state in onResetTunnel: %s' % self.tunState)

    def onClose(self, wasClean, code, reason, logWarn=True):
        self._closeAllPushToTun()
        if logWarn and not wasClean and reason:
            logging.warning('tunnel broken: ' + reason)
        if config.debug:
            self.allConn.remove(self)
            logging.debug('tunnel closed (total %d)' % len(self.allConn))

    def _closeAllPushToTun(self):
        for t in self._pushToTunTasks:
            t.cancel()
        self._pushToTunTasks.clear()
        self._exclusiveReader = self._exclusiveWriter = None
