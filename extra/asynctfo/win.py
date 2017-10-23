import socket
import errno
import sys
import _overlapped
from .overlapped import Overlapped
from asyncio.windows_events import IocpProactor, ProactorEventLoop


winver = sys.getwindowsversion()
if winver.major < 10 or winver.build < 14393:
    raise RuntimeError('TCP Fast Open is only available on Windows 10 Anniversary Update or later')


class TfoEventLoop(ProactorEventLoop):
    def __init__(self):
        super().__init__(IocpProactorWithTfo())

    def sock_connect_tfo(self, sock, address, dat):
        # dat is bytes object
        return self._proactor.connect_tfo(sock, address, dat)

    def create_server_tfo(self, *args, **kw):
        raise NotImplementedError

class IocpProactorWithTfo(IocpProactor):
    def connect_tfo(self, conn, address, dat):
        self._register_with_iocp(conn)
        # The socket needs to be locally bound before we call ConnectEx().
        try:
            _overlapped.BindLocal(conn.fileno(), conn.family)
        except OSError as e:
            if e.winerror != errno.WSAEINVAL:
                raise
            # Probably already locally bound; check using getsockname().
            if conn.getsockname()[1] == 0:
                raise
        ov = Overlapped(0)
        ov.ConnectEx(conn.fileno(), address, dat)

        def finish_connect(trans, key, ov):
            ov.getresult()
            # Use SO_UPDATE_CONNECT_CONTEXT so getsockname() etc work.
            conn.setsockopt(socket.SOL_SOCKET,
                            _overlapped.SO_UPDATE_CONNECT_CONTEXT, 0)
            return conn

        return self._register(ov, conn, finish_connect)
