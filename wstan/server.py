import asyncio
import logging
import base64
from autobahn.asyncio.websocket import WebSocketServerProtocol, WebSocketServerFactory
from autobahn.websocket.types import ConnectionDeny
from wstan.relay import RelayMixin
from wstan import parse_relay_request, loop, config


class WSTunServerProtocol(WebSocketServerProtocol, RelayMixin):
    def __init__(self):
        super().__init__()
        self.clientAddr = None
        self.clientPort = None
        self.connectTargetTask = None

    def onConnect(self, request):
        # this method can't be coroutine (framework limitation)
        # print(request.headers.get('sec-websocket-key'))
        try:
            initData = base64.b64decode(self.http_request_path[1:])
        except Exception:
            raise ConnectionDeny(404)
        try:
            addr, port, remainData = parse_relay_request(initData)
        except ValueError:
            raise ConnectionDeny(400)
        assert remainData
        self.connectTargetTask = asyncio.async(self.connectTarget(addr, port, remainData))

    @asyncio.coroutine
    def connectTarget(self, addr, port, data=None):
        # if data supplied, it will be sent after connection established
        try:
            reader, writer = yield from asyncio.open_connection(addr, port)
        except (ConnectionError, OSError, TimeoutError):
            logging.warning('failed to connect %s:%s (from %s:%s)' %
                            (addr, port, self.clientAddr, self.clientPort))
            return self.sendClose(3004, reason='failed to connect target')
        logging.info('relay %s:%s <--> %s:%s' %
                     (self.clientAddr, self.clientPort, addr, port))
        self.setProxy(reader, writer)
        if data:
            writer.write(data)
        self.connectTargetTask = None

    def onResetTunnel(self):
        # received reset before connected to target
        # there is a state which only exists in wstan server: connecting
        if self.tunState == self.TUN_STATE_IDLE:
            self.sendMessage(b'RST')
            self.connectTargetTask.cancel()
            self.connectTargetTask = None
            self.succeedReset()
        else:
            super().onResetTunnel()

    def onOpen(self):
        self.clientAddr, self.clientPort, *__ = self.transport.get_extra_info('peername')

    @asyncio.coroutine
    def onMessage(self, payload, isBinary):
        if not isBinary:
            assert payload == b'RST'
            return self.onResetTunnel()
        if self.tunState == self.TUN_STATE_IDLE:
            if self.connectTargetTask:
                logging.debug('data received while waiting for connectTargetTask')
                yield from asyncio.wait_for(self.connectTargetTask, None)
            try:
                addr, port, remainData = parse_relay_request(payload)
            except ValueError:
                return self.sendClose(3005, reason='invalid relay address info')
            self.connectTargetTask = asyncio.async(self.connectTarget(addr, port, remainData))
            return
        elif self.tunState == self.TUN_STATE_RESETTING:
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
    factory.autoPingInterval = 30
    factory.autoPingTimeout = 10

    server = loop.run_until_complete(loop.create_server(factory, addr, port))
    print('wstan server -- listen on %s:%d' % (addr, port))

    try:
        loop.run_forever()
    finally:
        server.close()
        loop.close()
