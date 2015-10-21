import asyncio
import logging
from autobahn.asyncio.websocket import WebSocketServerProtocol, WebSocketServerFactory
from wstan.relay import RelayMixin
from wstan import parse_relay_request, loop, config


class WSTunServerProtocol(RelayMixin, WebSocketServerProtocol):
    def __init__(self):
        RelayMixin.__init__(self)
        WebSocketServerProtocol.__init__(self)
        self.clientAddr = None
        self.clientPort = None

    def onOpen(self):
        self.clientAddr, self.clientPort, *__ = self.transport.get_extra_info('peername')

    @asyncio.coroutine
    def onMessage(self, payload, isBinary):
        if not isBinary:
            assert payload == b'RST'
            return self.onResetTunnel()

        if self.tunState == self.TUN_STATE_IDLE:
            try:
                addr, port, payload = parse_relay_request(payload)
            except (ValueError, IndexError):
                return self.sendClose(3005, reason='invalid relay address info')
            try:
                reader, writer = yield from asyncio.open_connection(addr, port)
            except (ConnectionError, OSError, TimeoutError):
                logging.warning('failed to connect %s:%d (from %s:%s)' %
                                (addr, port, self.clientAddr, self.clientPort))
                return self.sendClose(3004, reason='failed to connect target')
            logging.info('relay %s:%d  (from %s:%s)' %
                         (addr, port, self.clientAddr, self.clientPort))
            self.setProxy(reader, writer)
        elif self.tunState == self.TUN_STATE_RESETTING1:
            return
        self._writer.write(payload)

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
    factory.autoPingInterval = 9
    factory.autoPingTimeout = 2

    server = loop.run_until_complete(loop.create_server(factory, addr, port))
    print('wstan server -- listen on %s:%d' % (addr, port))

    try:
        loop.run_forever()
    finally:
        server.close()
        loop.close()
