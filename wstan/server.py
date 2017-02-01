import logging
import socket
import base64
import time
from collections import defaultdict
from asyncio import coroutine, async_, open_connection, sleep
from wstan.autobahn.asyncio.websocket import WebSocketServerProtocol, WebSocketServerFactory
from wstan.autobahn.websocket.types import ConnectionDeny
from wstan.relay import RelayMixin
from wstan import loop, config, die, get_sha1, Base64Error


# key is timestamp//10, value is list of nonce
# used to detect replay attack (temper bits of ciphertext and observe server's reaction)
# it will fail if genuine request being delayed
seenNonceByTime = defaultdict(set)


class WSTunServerProtocol(WebSocketServerProtocol, RelayMixin):
    PUSH_TO_TUN_CONN_ERR_MSG = 'connection to target broken'

    def __init__(self):
        WebSocketServerProtocol.__init__(self)
        RelayMixin.__init__(self)
        self.clientInfo = None
        self.connectTargetTask = None
        self._dataToTarget = bytearray()

    def onConnect(self, request):
        self.clientInfo = '{0}:{1}'.format(*self.transport.get_extra_info('peername'))
        # ----- init decryptor -----
        if not config.tun_ssl:
            if config.compatible:
                cookie = request.headers['cookie']
                if cookie.count(';') > 0:
                    raise ConnectionDeny(400)
                if not cookie.startswith(config.cookie_key + '='):
                    raise ConnectionDeny(400)
                nonceB64 = cookie.lstrip(config.cookie_key + '=')
            else:
                nonceB64 = request.headers['sec-websocket-key']
            try:
                nonce = base64.b64decode(nonceB64)
                self.initCipher(nonce, decryptor=True)
            except Exception as e:
                logging.error('failed to initialize cipher: %s' % e)
                raise ConnectionDeny(400)
        else:
            nonceB64 = nonce = None  # for decrypting

        # ----- extract header -----
        path = self.http_request_path
        try:
            if path.startswith(factory.path):
                path = path[len(factory.path):]
            dat = base64.urlsafe_b64decode(path[1:] if path.startswith('/') else path)
            cmd = ord(self.decrypt(dat[:1]))
            addr, port, remainData, timestamp = self.parseRelayHeader(dat)
            if cmd != self.CMD_REQ:
                raise ValueError('wrong command %s' % cmd)
        except (ValueError, Base64Error) as e:
            logging.error('invalid request: %s (from %s), path: %s' %
                          (e, self.clientInfo, path))
            raise ConnectionDeny(400)

        if not config.tun_ssl:
            # filter replay attack
            seen = seenNonceByTime[timestamp // 10]
            if nonce in seen:
                logging.warning('replay attack detected (from %s)' % self.clientInfo)
                raise ConnectionDeny(400)
            seen.add(nonce)

            if config.compatible:
                # avoid generating a new random nonce for encrypting, and client will do same
                # calculating to get this nonce
                encNonce = get_sha1(nonce)[:16]
            else:
                # repeat calculation in websocket library so that key in WS handshake reply
                # is the same as this one
                encNonce = get_sha1(nonceB64.encode() + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11")[:16]
            self.initCipher(encNonce, encryptor=True)

        self.tunOpen.set_result(None)
        self.connectTargetTask = async_(self.connectTarget(addr, port, remainData))

    @coroutine
    def connectTarget(self, addr, port, data):
        logging.info('requested %s <--> %s:%s' % (self.clientInfo, addr, port))
        try:
            reader, writer = yield from open_connection(addr, port)
        except (ConnectionError, OSError, TimeoutError) as e:
            logging.info("can't connect to %s:%s (from %s)" % (addr, port, self.clientInfo))
            return self.resetTunnel(reason="can't connect to target: %s" % e)
        self.setProxy(reader, writer)
        if data:
            writer.write(data)
        if self._dataToTarget:
            writer.write(self._dataToTarget)
            self._dataToTarget.clear()
        self.connectTargetTask = None

    # next 2 overrides deal with a implicit state which exists only in wstan server: CONNECTING
    # data received during CONNECTING will be sent after connected
    # IDLE --onConnect--> CONNECTING --connectTarget--> USING
    # CONNECTING --RST-received-and-RST-sent--> IDLE
    # CONNECTING --RST-sent--> RESETTING --RST-received--> IDLE
    def resetTunnel(self, reason=''):
        if self.connectTargetTask:
            self.connectTargetTask = None
            self._dataToTarget.clear()
            self.sendMessage(self.makeResetMessage(reason), True)
            self.tunState = self.TUN_STATE_RESETTING
        else:
            super().resetTunnel(reason)

    def onResetTunnel(self):
        if self.connectTargetTask:  # received reset before connected to target
            self.sendMessage(self.makeResetMessage(), True)
            self.connectTargetTask.cancel()
            self.connectTargetTask = None
            self._dataToTarget.clear()
            self.succeedReset()
        else:
            super().onResetTunnel()

    @coroutine
    def onMessage(self, dat, isBinary):
        if not isBinary:
            logging.error('non binary ws message received (from %s)' % self.clientInfo)
            return self.sendClose(3000)

        cmd = ord(self.decrypt(dat[:1]))
        if cmd == self.CMD_RST:
            try:
                msg = self.parseResetMessage(dat)
            except ValueError as e:
                logging.error('invalid reset message: %s (from %s)' % (e, self.clientInfo))
                return self.sendClose(3000)
            if not msg.startswith('  '):
                logging.info('tunnel abnormal reset: %s' % msg)
            self.onResetTunnel()
        elif cmd == self.CMD_REQ:
            try:
                if self.tunState != self.TUN_STATE_IDLE:
                    raise Exception('reset received when not idle')
                addr, port, remainData, __ = self.parseRelayHeader(dat)
            except Exception as e:
                logging.error('invalid request in reused tun: %s (from %s)' % (e, self.clientInfo))
                return self.sendClose(3000)
            self.connectTargetTask = async_(self.connectTarget(addr, port, remainData))
        elif cmd == self.CMD_DAT:
            dat = self.decrypt(dat[1:])
            if self.tunState == self.TUN_STATE_RESETTING:
                return
            if self.connectTargetTask:
                self._dataToTarget += dat
                return
            self._writer.write(dat)
        else:
            logging.error('wrong command: %s (from %s)' % (cmd, self.clientInfo))
            self.sendClose(3000)

    def sendServerStatus(self, redirectUrl=None, redirectAfter=0):
        return super().sendServerStatus(redirectUrl, redirectAfter) if redirectUrl else self.sendHtml('')

    def onClose(self, wasClean, code, reason, logWarn=True):
        """Logging failed requests."""
        logWarn = True
        if reason and not self.tunOpen.done():
            peer = '{0}:{1}'.format(*self.transport.get_extra_info('peername'))  # self.clientInfo is None
            logging.warning(reason + ' (from %s)' % peer)
            logWarn = False

        RelayMixin.onClose(self, wasClean, code, reason, logWarn=logWarn)


@coroutine
def clean_seen_nonce():
    # it's unnecessary to clean expired one in time
    while True:
        yield from sleep(120)
        expire_time = (time.time() - WSTunServerProtocol.REQ_TTL) // 10
        expired = list(filter(lambda t: t < expire_time, seenNonceByTime.keys()))
        for k in expired:
            del seenNonceByTime[k]


def silent_timeout_err_handler(loop_, context):
    """Prevent asyncio from logging annoying TimeoutError."""
    if 'exception' in context and not isinstance(context['exception'], TimeoutError):
        loop_.default_exception_handler(context)


factory = WebSocketServerFactory(config.uri)
factory.protocol = WSTunServerProtocol
factory.server = ''  # hide Server field of handshake HTTP header
factory.autoPingInterval = 400  # only used to clear half-open connections
factory.autoPingTimeout = 30
factory.openHandshakeTimeout = 8  # timeout after TCP established and before succeeded WS handshake
factory.closeHandshakeTimeout = 10


def main():
    addr = config.tun_addr or config.uri_addr
    port = config.tun_port or config.uri_port

    try:
        server = loop.run_until_complete(loop.create_server(factory, addr, port))
    except OSError:
        die('wstan server failed to bind on %s:%d' % (addr, port))
    so = server.sockets[0]
    if len(server.sockets) == 1 and so.family == socket.AF_INET6 and hasattr(socket, 'IPPROTO_IPV6'):
        # force user to specify URI in wstan server is a bad design, this try to fix
        # inconvenience in dual stack server
        so.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)  # default 1 in Linux

    loop.set_exception_handler(silent_timeout_err_handler)
    async_(clean_seen_nonce())

    print('wstan server -- listening on %s:%d' % (addr, port))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        loop.close()
