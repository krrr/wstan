###############################################################################
#
# The MIT License (MIT)
#
# Copyright (c) Tavendo GmbH
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
###############################################################################


# WebSocket protocol support
import socket
import asyncio
from wstan.autobahn.asyncio.websocket import \
    WebSocketServerProtocol, \
    WebSocketClientProtocol, \
    WebSocketServerFactory, \
    WebSocketClientFactory


__all__ = (
    'WebSocketServerProtocol',
    'WebSocketClientProtocol',
    'WebSocketServerFactory',
    'WebSocketClientFactory',
)

@asyncio.coroutine
def create_sock(host, port, *, family=0, proto=0, flags=0):
    """Similar to sock_connect, with sock object creation, and it resolve names for Py 3.4- capability."""
    assert host is not None and port is not None
    loop = asyncio.get_event_loop()

    infos = yield from loop.getaddrinfo(
            host, port, family=family,
            type=socket.SOCK_STREAM, proto=proto, flags=flags)
    if not infos:
        raise OSError('getaddrinfo() returned empty list')

    exceptions = []
    for family, type, proto, cname, address in infos:
        try:
            sock = socket.socket(family=family, type=type, proto=proto)
            sock.setblocking(False)
            yield from loop.sock_connect(sock, address)
        except OSError as exc:
            if sock is not None:
                sock.close()
            exceptions.append(exc)
        except Exception:
            if sock is not None:
                sock.close()
            raise
        else:
            break
    else:
        if len(exceptions) == 1:
            raise exceptions[0]
        else:
            # If they all have the same str(), raise one.
            model = str(exceptions[0])
            if all(str(exc) == model for exc in exceptions):
                raise exceptions[0]
            # Raise a combined exception so the user can see all
            # the various error messages.
            raise OSError('Multiple exceptions: {}'.format(
                ', '.join(str(exc) for exc in exceptions)))

    return sock
