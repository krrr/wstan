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


@asyncio.coroutine
def create_sock(host, port, *,
                family=0, proto=0, flags=0,
                local_addr=None):
    """Copied from asyncio create_connection function. It return raw socket
    instead of transport and protocol. SSL is not supported."""
    loop = asyncio.get_event_loop()

    if host is None or port is None:
        raise ValueError('host and port was not specified and no sock specified')

    f1 = loop.getaddrinfo(
            host, port, family=family,
            type=socket.SOCK_STREAM, proto=proto, flags=flags)
    fs = [f1]
    if local_addr is not None:
        f2 = loop.getaddrinfo(
                *local_addr, family=family,
                type=socket.SOCK_STREAM, proto=proto, flags=flags)
        fs.append(f2)
    else:
        f2 = None

    yield from asyncio.wait(fs, loop=loop)

    infos = f1.result()
    if not infos:
        raise OSError('getaddrinfo() returned empty list')
    if f2 is not None:
        laddr_infos = f2.result()
        if not laddr_infos:
            raise OSError('getaddrinfo() returned empty list')

    exceptions = []
    for family, type, proto, cname, address in infos:
        try:
            sock = socket.socket(family=family, type=type, proto=proto)
            sock.setblocking(False)
            if f2 is not None:
                for _, _, _, _, laddr in laddr_infos:
                    try:
                        sock.bind(laddr)
                        break
                    except OSError as exc:
                        exc = OSError(
                                exc.errno, 'error while '
                                           'attempting to bind on address '
                                           '{!r}: {}'.format(
                                        laddr, exc.strerror.lower()))
                        exceptions.append(exc)
                else:
                    sock.close()
                    sock = None
                    continue
            yield from loop.sock_connect(sock, address)
        except OSError as exc:
            if sock is not None:
                sock.close()
            exceptions.append(exc)
        except:
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


__all__ = (
    'WebSocketServerProtocol',
    'WebSocketClientProtocol',
    'WebSocketServerFactory',
    'WebSocketClientFactory',
)
