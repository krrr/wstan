import asyncio
import logging
import base64
from binascii import Error as Base64Error
from autobahn.asyncio.websocket import WebSocketServerProtocol, WebSocketServerFactory
from autobahn.websocket.types import ConnectionDeny
from wstan.relay import RelayMixin
from wstan import loop, config


class WSTunServerProtocol(WebSocketServerProtocol, RelayMixin):
    def __init__(self):
        super().__init__()
        self.clientAddr = None
        self.clientPort = None
        self.connectTargetTask = None

    def onConnect(self, request):
        if config.key:  # setup crypto
            nonce = base64.b64decode(request.headers['sec-websocket-key'])
            self.initCrypto(nonce)

        self.clientAddr, self.clientPort, *__ = self.transport.get_extra_info('peername')
        try:
            dat = base64.urlsafe_b64decode(self.http_request_path[1:])
            cmd = int.from_bytes(self.decryptor.update(dat[:1]), 'big') if self.cipher else dat[0]
            if cmd != self.CMD_REQ:
                raise ValueError('wrong command %s' % cmd)
            addr, port, remainData = self.parseRelayHeader(dat)
        except (ValueError, Base64Error) as e:
            logging.error('invalid header: %s (from %s:%s), path:%s' %
                          (e, self.clientAddr, self.clientPort, self.http_request_path))
            raise ConnectionDeny(400)
        self.connectTargetTask = asyncio.async(self.connectTarget(addr, port, remainData))

    @asyncio.coroutine
    def connectTarget(self, addr, port, data):
        try:
            reader, writer = yield from asyncio.open_connection(addr, port)
        except (ConnectionError, OSError, TimeoutError) as e:
            logging.warning('failed to connect %s:%s (from %s:%s)' %
                            (addr, port, self.clientAddr, self.clientPort))
            self.resetTunnel(reason='failed to connect target: %s' % e)
            return
        logging.info('relay %s:%s <--> %s:%s' %
                     (self.clientAddr, self.clientPort, addr, port))
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
            super().resetTunnel()

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
            logging.error('non binary ws message received')
            return self.sendClose(3000)

        # TODO: log more info
        cmd = int.from_bytes(self.decryptor.update(dat[:1]), 'big') if self.cipher else dat[0]
        if cmd == self.CMD_RST:
            msg = self.parseResetMessage(dat)
            if not msg.startswith('  '):
                logging.info('tunnel abnormal reset: %s' % msg)
            self.onResetTunnel()
        elif cmd == self.CMD_REQ:
            try:
                if self.tunState != self.TUN_STATE_IDLE:
                    raise ValueError('wrong command %s' % cmd)
                addr, port, remainData = self.parseRelayHeader(dat)
            except ValueError as e:
                logging.error('invalid header in reused tun: %s (from %s:%s), dat:%s' %
                              (e, self.clientAddr, self.clientPort, dat))
                return self.sendClose(3000)
            if self.connectTargetTask:
                logging.debug('relay request received when connectTargetTask running')
                # will order of messages be changed by waiting?
                yield from asyncio.wait_for(self.connectTargetTask, None)
            self.connectTargetTask = asyncio.async(self.connectTarget(addr, port, remainData))
        elif cmd == self.CMD_DAT:
            dat = self.decryptor.update(dat[1:]) if self.cipher else dat[1:]
            if self.tunState == self.TUN_STATE_RESETTING:
                return
            if self.connectTargetTask:
                logging.debug('data received when connectTargetTask running')
                yield from asyncio.wait_for(self.connectTargetTask, None)
            self._writer.write(dat)
        else:
            logging.error('wrong command')
            # TODO: random drop

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
