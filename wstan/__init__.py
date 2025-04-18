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
import logging
import socket
import struct
import hashlib
import asyncio
import base64
import sys
import os
import re
import argparse
import ipaddress
from binascii import Error as Base64Error
from configparser import ConfigParser, ParsingError
from collections import deque
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from wstan.autobahn.websocket.protocol import parseWsUrl

__version__ = '0.5.0'


# Don't use "super().__init__()" in constructor of classes of this package (all libraries
# used are using old style)

# global variables shared between modules
config: argparse.Namespace
loop: asyncio.AbstractEventLoop

_http_req = re.compile(rb'^(GET|POST|HEAD|CONNECT|OPTIONS|PUT|DELETE|TRACE|PATCH) ')
_accept_html = re.compile(rb'^Accept:[^\r]*text/html', re.IGNORECASE)
_keep_alive = re.compile(rb'^Connection:[^\r]*keep-alive$', re.IGNORECASE)
_error_page = '''<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <title>wstan error</title>
    <style type="text/css">
      body {{
        font-family: sans-serif;
        font-size: 12pt;
        height: 100%;
      }}
      h1 {{
        font-size: 18pt;
        color: #333;
      }}
      #frame {{
        margin: 0 auto;
        margin-top: 80px;
        width: 80%;
        color: #444;
      }}
      hr {{ color: #BBB }}
    </style>
  </head>
  <body>
    <div id="frame">
      <h1>wstan error: {title}</h1>
      <hr />
      <p>{detail}</p>
    </div>
  </body>
</html>
'''
KDF_SALT = b'j\xbf \t;\xd5\xc6\xc6vh\x07\xc1\xd6\xb2\x82/'


async def my_sock_connect(host=None, port=None, *, family=0, proto=0, flags=0) -> socket.socket:
    """Modified version of BaseEventLoop.create_connection: this function returns sock object.
    And it resolve names for Py 3.4- capability."""
    assert (host and port)

    infos = await loop.getaddrinfo(
        host, port, family=family,
        type=socket.SOCK_STREAM, proto=proto, flags=flags)
    if not infos:
        raise OSError('getaddrinfo() returned empty list')

    exceptions = []
    sock = None
    for family, type_, proto, cname, address in infos:
        try:
            sock = socket.socket(family=family, type=type_, proto=proto)
            sock.setblocking(False)
            await loop.sock_connect(sock, address)
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
            model = str(exceptions[0])
            if all(str(exc) == model for exc in exceptions):  # If they all have the same str(), raise one.
                raise exceptions[0]
            raise OSError('Multiple exceptions: {}'.format(', '.join(map(str, exceptions))))

    return sock


def make_socks5_addr(host: str, port: int):
    try:
        addr = ipaddress.ip_address(host)
        if isinstance(addr, ipaddress.IPv4Address):
            atyp = b'\x01'
            addr = socket.inet_aton(host)
        else:  # IPv6
            atyp = b'\x04'
            addr = socket.inet_pton(socket.AF_INET6, host)
    except ValueError:
        atyp = b'\x03'  # domain name
        addr = host.encode()
        addr = bytes([len(addr)]) + addr
    return b'\x00' + atyp + addr + struct.pack('>H', port)


def parse_socks5_addr(dat, allow_remain=False):
    """Extract address and port from SOCKS5 request header (only 4 parts:
    RSV(0x00) | ATYP | DST.ADDR | DST.PORT). The header will be reused in tunnel server."""
    if not dat or dat[0] != 0x00:
        raise ValueError('RSV not 0x00')
    try:
        atyp = dat[1]
        if atyp == 0x01:  # IPv4
            port_idx = 6
            target_addr = socket.inet_ntoa(dat[2:port_idx])
        elif atyp == 0x03:  # domain name
            port_idx = 3 + dat[2]
            target_addr = dat[3:port_idx].decode('ascii')
        elif atyp == 0x04:  # IPv6
            port_idx = 18
            target_addr = socket.inet_ntop(socket.AF_INET6, dat[2:port_idx])
        else:
            raise ValueError("unknown address type")
        target_port = struct.unpack('>H', dat[port_idx:port_idx+2])[0]
        if allow_remain:
            return target_addr, target_port, port_idx + 2
        else:
            if dat[port_idx+2:]:
                raise ValueError
            return target_addr, target_port
    except (IndexError, struct.error):
        raise ValueError


def parse_sock5_udp_addr(dat):
    """Extract address and port from SOCKS5 UDP request header. Parts:
    RSV(0x0000) | FRAG | ATYP | DST.ADDR | DST.PORT. """
    if not dat or dat[0] != 0x00 or dat[1] != 0x00:
        raise ValueError('RSV not 0x0000')
    elif dat[2] != 0x00:
        raise ValueError("fragment not supported, FRAG must be 0")
    target_addr, target_port, remain_idx = parse_socks5_addr(dat[2:], True)
    return target_addr, target_port, remain_idx + 2


def die(reason):
    print(reason, file=sys.stderr)
    sys.exit(1)


def load_ini(ini_path):
    """Read config from ini file."""
    ini = ConfigParser()
    try:
        # utf-8 with BOM will kill ConfigParser
        with open(ini_path, encoding='utf-8-sig') as f:
            ini.read_string('[DEFAULT]\n' + f.read())
    except (ParsingError, FileNotFoundError) as e:
        die('error reading config file: %s' % e)
    ini = ini['DEFAULT']

    ret = {}
    ret.update(ini)
    # fix types
    for i in ('port', 'tun-port'):
        if i in ini:
            ret[i] = ini.getint(i)
    for i in ('client', 'server', 'debug', 'compatible'):
        if i in ini:
            ret[i] = ini.getboolean(i)

    for i in ret:
        if '-' in i:
            ret[i.replace('-', '_')] = ret.pop(i)
    return ret.items()


def load_config():
    parser = argparse.ArgumentParser(
        description='Ver %s | Tunneling TCP in WebSocket' % __version__)
    # common config
    parser.add_argument('-g', '--gen-key', help='generate a 16 byte base64 key and exit', action='store_true')
    parser.add_argument('uri', help='URI of server', nargs='?')
    parser.add_argument('key', help='password or generated key', nargs='?')
    g = parser.add_mutually_exclusive_group()
    g.add_argument('-c', '--client', help='run as client (default, also act as SOCKS/HTTP server)',
                   default=True, action='store_true')
    g.add_argument('-s', '--server', help='run as server', action='store_true')
    parser.add_argument('-d', '--debug', action='store_true')
    parser.add_argument('-z', '--compatible', help='useful when server is behind WS proxy', action='store_true')
    parser.add_argument('-i', '--ini', help='load config file')
    # client config
    client_group = parser.add_argument_group('client options')
    client_group.add_argument('-y', '--proxy', help='use HTTP proxy to connect to wstan server (host:port)')
    client_group.add_argument('-a', '--addr', help='listen address of SOCKS/HTTP server (defaults localhost)',
                              default='localhost')
    client_group.add_argument('-p', '--port', help='listen port of SOCKS/HTTP server (defaults 1080)',
                              type=int, default=1080)
    client_group.add_argument('--pool-size', help='max size of connection pool (defaults 16)',
                              type=int, default=16)
    client_group.add_argument('--pool-max-idle', help='max idle timeout of connection pool in sec (defaults 300)',
                              type=int, default=300)
    # server config
    server_group = parser.add_argument_group('server options')
    server_group.add_argument('-t', '--tun-addr', help='listen address of server, overrides URI')
    server_group.add_argument('-r', '--tun-port', help='listen port of server, overrides URI', type=int)
    server_group.add_argument('--x-forward', help='use X-Forwarded-For as client IP address when behind proxy',
                              default=False, action='store_true')
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.gen_key:  # option -g can be used without URI and key, just like -h
        return args

    if args.ini:
        for k, v in load_ini(args.ini):
            setattr(args, k, v)  # file config will override args

    for i in ['uri', 'key']:
        if not getattr(args, i):
            die('%s not specified' % i)

    if '?' in args.uri:
        die('URI should not contain query')

    try:
        bin_key = base64.b64decode(args.key)
        assert len(bin_key) == 16
    except (Base64Error, AssertionError):
        # derive key from password
        kdf = Scrypt(salt=KDF_SALT, length=32, n=2**14, r=8, p=1)
        bin_key = kdf.derive(args.key.encode())
    args.bin_key = bin_key

    args.tun_ssl, args.uri_addr, args.uri_port = parseWsUrl(args.uri)[:3]
    if args.proxy and args.client:
        try:
            args.proxy_host, port = args.proxy.split(':')
            args.proxy_port = int(port)
        except ValueError:
            dir('invalid proxy format')
    if args.compatible:
        d = get_sha1(args.key)[-1]
        args.cookie_key = '_' + chr((d % 26) + 65)  # an upper case character
    return args


def http_die_soon(req):
    """Disable keep-alive to make HTTP proxy act like SOCKS. By doing this
    wstan server can remain unchanged, but it will increase latency."""
    dropped = [i for i in req.split(b'\r\n') if not _keep_alive.match(i)]
    end = dropped.index(b'')
    return b'\r\n'.join(dropped[:end] + [b'Connection: close'] + dropped[end:])


def is_http_req(dat):
    return bool(_http_req.match(dat))


def can_return_error_page(dat):
    return dat and bool(_http_req.match(dat) and any(map(_accept_html.match, dat.split(b'\r\n'))))


def gen_error_page(title, detail):
    body = _error_page.format(title=title, detail=detail).encode()
    header = '\r\n'.join(
        ['HTTP/1.1 599 WSTAN ERROR', 'Content-Type: text/html; charset=UTF-8',
         'Content-Length: %d' % len(body), '', '']).encode()
    return header + body


def get_sha1(dat):
    sha1 = hashlib.sha1()
    sha1.update(dat)
    return sha1.digest()


class InMemoryLogHandler(logging.Handler):
    logs = deque(maxlen=200)

    def emit(self, record):
        self.logs.append(self.format(record))


def main_entry():
    if not sys.version_info >= (3, 3):
        die('Python 3.3 or higher required')

    global config, loop
    config = load_config()

    if config.gen_key:
        return print('A fresh random key:', base64.b64encode(os.urandom(16)).decode())

    logging.basicConfig(level=logging.DEBUG if config.debug else logging.INFO,
                        format='%(asctime)s %(levelname).1s: %(message)s',
                        datefmt='%m-%d %H:%M:%S')

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    if config.client:
        h = InMemoryLogHandler()
        logging.getLogger().addHandler(h)
        h.setFormatter(logging.Formatter('%(asctime)s %(levelname).1s: %(message)s', '%H:%M:%S'))
        h.setLevel(logging.DEBUG if config.debug else logging.INFO)

    if config.debug and hasattr(loop, 'set_debug'):
        loop.set_debug(True)
        logging.getLogger('asyncio').setLevel(logging.WARNING)

    if config.server:
        from wstan.server import main
    else:
        from wstan.client import main
    main()
