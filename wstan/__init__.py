# Copyright (c) 2017 krrr
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
from binascii import Error as Base64Error
from collections import deque

__version__ = '0.3.1'

# patch asyncio because "async" will become a keyword sooner or later
asyncio.async_ = getattr(asyncio, 'ensure_future', None) or getattr(asyncio, 'async')

# Don't use "super().__init__()" in constructor of classes of this package (all libraries
# used are using old style)

# global variables shared between modules
config = loop = None

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


def make_socks_addr(host, port):
    return b'\x00\x03' + bytes([len(host)]) + host + struct.pack('>H', port)


def parse_socks_addr(dat, allow_remain=False):
    """Extract address and port from SOCKS request header (only 4 parts:
    RSV(0x00) | ATYP | DST.ADDR | DST.PORT). The header will be reused in tunnel server."""
    if not dat or dat[0] != 0x00:
        raise ValueError
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
            raise ValueError
        target_port = struct.unpack('>H', dat[port_idx:port_idx+2])[0]
        if allow_remain:
            return target_addr, target_port, port_idx + 2
        else:
            if dat[port_idx+2:]:
                raise ValueError
            return target_addr, target_port
    except (IndexError, struct.error):
        raise ValueError


def die(reason):
    print(reason, file=sys.stderr)
    sys.exit(1)


def load_config():
    import argparse
    from wstan.autobahn.websocket.protocol import parseWsUrl

    parser = argparse.ArgumentParser(
        description='Ver %s | Tunneling TCP in WebSocket' % __version__)
    # common config
    parser.add_argument('-g', '--gen-key', help='generate a key and exit', action='store_true')
    parser.add_argument('uri', help='URI of server', nargs='?')
    parser.add_argument('key', help='base64 encoded 16-byte key', nargs='?')
    g = parser.add_mutually_exclusive_group()
    g.add_argument('-c', '--client', help='run as client (default, also act as SOCKS5/HTTP(S) server)',
                   default=True, action='store_true')
    g.add_argument('-s', '--server', help='run as server', action='store_true')
    parser.add_argument('-d', '--debug', action='store_true')
    parser.add_argument('-z', '--compatible', help='useful when server is behind WS proxy', action='store_true')
    # client config
    parser.add_argument('-y', '--proxy', help='let client use a HTTPS proxy (host:port)')
    parser.add_argument('-p', '--port', help='listen port of SOCKS5/HTTP(S) server at localhost (defaults 1080)',
                        type=int, default=1080)
    # server config
    parser.add_argument('-t', '--tun-addr', help='listen address of server, overrides URI')
    parser.add_argument('-r', '--tun-port', help='listen port of server, overrides URI', type=int)
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    if args.gen_key:  # option -g can be used without URI and key, just like -h
        return args
    for i in ['uri', 'key']:
        if not getattr(args, i):
            die('%s not specified' % i)

    if '?' in args.uri:
        die('URI should not contain query')

    try:
        args.key = base64.b64decode(args.key)
        assert len(args.key) == 16
    except (Base64Error, AssertionError):
        die('invalid key')

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

    loop = asyncio.get_event_loop()
    logging.basicConfig(level=logging.DEBUG if config.debug else logging.INFO,
                        format='%(asctime)s %(levelname).1s: %(message)s',
                        datefmt='%m-%d %H:%M:%S')
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
