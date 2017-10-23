import os
import sys
import errno
import socket
import itertools
import collections
from asyncio import coroutine, base_events, tasks
from asyncio.base_events import Server
from asyncio.unix_events import _UnixSelectorEventLoop


MSG_FASTOPEN = 0x20000000
TCP_FASTOPEN = 23


class TfoEventLoop(_UnixSelectorEventLoop):
    @coroutine
    def sock_connect_tfo(self, sock, address, dat):
        assert not hasattr(socket, 'AF_UNIX') or sock.family != socket.AF_UNIX

        resolved = base_events._ensure_resolved(
            address, family=sock.family, proto=sock.proto, loop=self)
        if not resolved.done():
            yield from resolved
        _, _, _, _, address = resolved.result()[0]

        fut = self.create_future()
        self._sock_connect_tfo(fut, sock, address, dat)
        return (yield from fut)

    def _sock_connect_tfo(self, fut, sock, address, dat):
        fd = sock.fileno()
        try:
            sent = sock.sendto(dat, MSG_FASTOPEN, address)
        except (BlockingIOError, InterruptedError):
            # no data sent! deal with it using sock_sendall
            # happen when fallback to 3-way handshake
            fut.add_done_callback(lambda _: self.remove_writer(fd))
            self.add_writer(fd, self._sock_connect_tfo_cb, fut, sock, address, dat)
        except Exception as exc:
            if isinstance(exc, OSError) and exc.errno == errno.ENOTCONN:
                fut.set_exception(RuntimeError('TCP Fast Open unavailable'))
            else:
                fut.set_exception(exc)
        else:
            if sent == len(dat):
                fut.set_result(None)
            else:
                # meaningless because too large data can't fit into the TCP SYN packet
                # or will it happen even when data can fit?
                # just keep consistency with fallback situation
                self._sock_sendall(fut, False, sock, dat[sent:])

    def _sock_connect_tfo_cb(self, fut, sock, address, dat):
        if fut.cancelled():
            return

        try:
            err = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if err != 0:
                raise OSError(err, 'ConnectTfo failed %s' % (address,))  # Jump to any except clause below.
        except (BlockingIOError, InterruptedError):
            # socket is still registered, the callback will be retried later
            pass
        except Exception as exc:
            fut.set_exception(exc)
        else:
            if dat:
                self._sock_sendall(fut, False, sock, dat)
            else:
                fut.set_result(None)

    @coroutine
    def create_server_tfo(self, protocol_factory, host=None, port=None,
                      *,
                      family=socket.AF_UNSPEC,
                      flags=socket.AI_PASSIVE,
                      sock=None,
                      backlog=100,
                      ssl=None,
                      reuse_address=None):
        if isinstance(ssl, bool):
            raise TypeError('ssl argument must be an SSLContext or None')
        if host is not None or port is not None:
            if sock is not None:
                raise ValueError(
                    'host/port and sock can not be specified at the same time')

            AF_INET6 = getattr(socket, 'AF_INET6', 0)
            if reuse_address is None:
                reuse_address = os.name == 'posix' and sys.platform != 'cygwin'
            sockets = []
            if host == '':
                hosts = [None]
            elif (isinstance(host, str) or
                  not isinstance(host, collections.Iterable)):
                hosts = [host]
            else:
                hosts = host

            fs = [self._create_server_getaddrinfo(host, port, family=family,
                                                  flags=flags)
                  for host in hosts]
            infos = yield from tasks.gather(*fs, loop=self)
            infos = set(itertools.chain.from_iterable(infos))

            completed = False
            try:
                for res in infos:
                    af, socktype, proto, canonname, sa = res
                    try:
                        sock = socket.socket(af, socktype, proto)
                    except socket.error:
                        continue
                    sockets.append(sock)
                    if reuse_address:
                        sock.setsockopt(
                            socket.SOL_SOCKET, socket.SO_REUSEADDR, True)

                    # set TCP_FASTOPEN
                    sock.setsockopt(socket.SOL_TCP, TCP_FASTOPEN, 20)  # last arg is max_pending_tfo_request

                    if af == AF_INET6 and hasattr(socket, 'IPPROTO_IPV6'):
                        sock.setsockopt(socket.IPPROTO_IPV6,
                                        socket.IPV6_V6ONLY,
                                        True)
                    try:
                        sock.bind(sa)
                    except OSError as err:
                        raise OSError(err.errno, 'error while attempting '
                                                 'to bind on address %r: %s'
                                      % (sa, err.strerror.lower()))
                completed = True
            finally:
                if not completed:
                    for sock in sockets:
                        sock.close()
        else:
            if sock is None:
                raise ValueError('Neither host/port nor sock were specified')
            if not (sock.type & socket.SOCK_STREAM) == socket.SOCK_STREAM:
                raise ValueError(
                    'A Stream Socket was expected, got {!r}'.format(sock))
            sockets = [sock]

        server = Server(self, sockets)
        for sock in sockets:
            sock.listen(backlog)
            sock.setblocking(False)
            self._start_serving(protocol_factory, sock, ssl, server, backlog)
        return server
