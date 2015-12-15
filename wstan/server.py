import asyncio
import logging
import base64
from wstan.autobahn.asyncio.websocket import WebSocketServerProtocol, WebSocketServerFactory
from wstan.autobahn.websocket.types import ConnectionDeny
from wstan.relay import RelayMixin
from wstan import loop, config, get_sha1, Base64Error


class WSTunServerProtocol(WebSocketServerProtocol, RelayMixin):
    def __init__(self):
        super().__init__()
        self.clientInfo = None
        self.connectTargetTask = None

    def onConnect(self, request):
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
            nonce = base64.b64decode(nonceB64)
            try:
                self.initCipher(nonce, decryptor=True)
            except Exception as e:
                logging.error('failed to initialize cipher: %s' % e)
                raise ConnectionDeny(400)
        else:
            nonceB64 = nonce = None  # for decrypting

        self.clientInfo = '%s:%s' % self.transport.get_extra_info('peername')[:2]
        try:
            dat = base64.urlsafe_b64decode(self.http_request_path[1:])
            cmd = ord(self.decrypt(dat[:1]))
            if cmd != self.CMD_REQ:
                raise ValueError('wrong command %s' % cmd)
            addr, port, remainData = self.parseRelayHeader(dat)
        except (ValueError, Base64Error) as e:
            logging.error('invalid header: %s (from %s), path: %s' %
                          (e, self.clientInfo, self.http_request_path))
            raise ConnectionDeny(400)

        if not config.tun_ssl:
            if config.compatible:
                # avoid generating a new random nonce for encrypting, and client will do same
                # calculating to get this nonce
                encNonce = get_sha1(nonce)[:16]
            else:
                # repeat calculation in websocket library so that key in WS handshake reply
                # is the same as this one
                encNonce = get_sha1(nonceB64.encode() + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11")[:16]
            self.initCipher(encNonce, encryptor=True)

        self.connectTargetTask = asyncio.async(self.connectTarget(addr, port, remainData))

    @asyncio.coroutine
    def connectTarget(self, addr, port, data):
        try:
            reader, writer = yield from asyncio.open_connection(addr, port)
        except (ConnectionError, OSError, TimeoutError) as e:
            logging.info('failed to connect %s:%s (from %s)' % (addr, port, self.clientInfo))
            return self.resetTunnel(reason='failed to connect target: %s' % e)
        logging.info('relay %s <--> %s:%s' % (self.clientInfo, addr, port))
        self.setProxy(reader, writer)
        assert data, 'some data must be sent after connected to target'
        writer.write(data)
        self.connectTargetTask = None

    # next 2 overrides deal with a state which exists only in wstan server: CONNECTING
    def resetTunnel(self, reason=''):
        if self.tunState == self.TUN_STATE_IDLE:
            assert self.connectTargetTask
            self.connectTargetTask = None
            self.sendMessage(self.makeResetMessage(reason), True)
            self.tunState = self.TUN_STATE_RESETTING
        else:
            super().resetTunnel(reason)

    def onResetTunnel(self):
        if self.tunState == self.TUN_STATE_IDLE:  # received reset before connected to target
            self.sendMessage(self.makeResetMessage(), True)
            self.connectTargetTask.cancel()
            self.connectTargetTask = None
            self.succeedReset()
        else:
            super().onResetTunnel()

    @asyncio.coroutine
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
                    raise ValueError('wrong command %s' % cmd)
                addr, port, remainData = self.parseRelayHeader(dat)
            except ValueError as e:
                logging.error('invalid header in reused tun: %s (from %s)' % (e, self.clientInfo))
                return self.sendClose(3000)
            if self.connectTargetTask:
                logging.debug('relay request received when connectTargetTask running')
                # will order of messages be changed by waiting?
                yield from asyncio.wait_for(self.connectTargetTask, None)
            self.connectTargetTask = asyncio.async(self.connectTarget(addr, port, remainData))
        elif cmd == self.CMD_DAT:
            dat = self.decrypt(dat[1:])
            if self.tunState == self.TUN_STATE_RESETTING:
                return
            if self.connectTargetTask:
                logging.debug('data received when connectTargetTask running')
                yield from asyncio.wait_for(self.connectTargetTask, None)
            self._writer.write(dat)
        else:
            logging.error('wrong command: %s (from %s)' % (cmd, self.clientInfo))
            self.sendClose(3000)

    def sendServerStatus(self, redirectUrl=None, redirectAfter=0):
        return super().sendServerStatus(redirectUrl, redirectAfter) if redirectUrl else self.sendHtml('')


def main():
    addr = config.uri_addr if config.tun_addr is None else config.tun_addr
    port = config.tun_port or config.uri_port
    uri = config.uri
    if config.tun_port and config.tun_port != config.uri_port:
        uri = uri.replace(':%d' % config.uri_port, ':%d' % config.tun_port)
    factory = WebSocketServerFactory(uri)
    factory.protocol = WSTunServerProtocol
    factory.server = ''  # hide Server field of handshake HTTP header
    factory.autoPingInterval = 30
    factory.autoPingTimeout = 10

    server = loop.run_until_complete(loop.create_server(factory, addr, port))
    print('wstan server -- listen on %s:%d' % (addr, port))

    try:
        loop.run_forever()
    finally:
        server.close()
        loop.close()
