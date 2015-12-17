import logging
import socket
import struct
import hashlib
import base64
import sys
import os
import re
from binascii import Error as Base64Error

__version__ = '0.1'

# global variables shared between modules
config = loop = None

_accept_html = re.compile(rb'^Accept:.*text/html', re.IGNORECASE)
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


def parse_socks_addr(dat, allow_remain=False):
    """Extract address and port from SOCKS request header (only 4 parts:
    RSV(0x00) | ATYP | DST.ADDR | DST.PORT). Those fields will be reused in tunnel server."""
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


def load_config():
    import argparse
    from wstan.autobahn.websocket.protocol import parseWsUrl

    parser = argparse.ArgumentParser(description='wstan')
    # common config
    parser.add_argument('-g', '--gen-key', help='generate a key and exit', action='store_true')
    parser.add_argument('uri', help='URI of server', nargs='?')
    parser.add_argument('key', help='base64 encoded 16-byte key', nargs='?')
    g = parser.add_mutually_exclusive_group()
    g.add_argument('-c', '--client', help='run as client (default, also act as SOCKS v5 server)',
                   action='store_true')
    g.add_argument('-s', '--server', help='run as server', action='store_true')
    parser.add_argument('-d', '--debug', action='store_true')
    parser.add_argument('-z', '--compatible', help='usable when server is behind WS proxy', action='store_true')
    # local side config
    parser.add_argument('-p', '--port', help='listen port of SOCKS server at localhost (defaults 1080)',
                        type=int, default=1080)
    # remote side config
    parser.add_argument('-t', '--tun-addr', help='listen address of server, override URI')
    parser.add_argument('-r', '--tun-port', help='listen port of server, override URI', type=int)
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    if args.gen_key:  # option -g can be used without URI and key, just like -h
        return args
    for i in ['uri', 'key']:
        if not getattr(args, i):
            print('error: %s required' % i)
            sys.exit(1)

    try:
        args.key = base64.b64decode(args.key)
        assert len(args.key) == 16
    except (Base64Error, AssertionError):
        print('error: invalid key')
        sys.exit(1)
    args.tun_ssl, args.uri_addr, args.uri_port = parseWsUrl(args.uri)[:3]
    if args.compatible:
        d = get_sha1(args.key)[-1]
        args.cookie_key = '_' + chr((d % 26) + 65)  # an upper case character
    return args


def can_return_error_page(dat):
    if not dat.startswith(b'GET'):
        return False
    if not any(_accept_html.match(i) for i in dat.split(b'\r\n')):
        return False
    return True


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


def main_entry():
    import asyncio

    global config, loop
    config = load_config()
    loop = asyncio.get_event_loop()
    logging.basicConfig(level=logging.DEBUG if config.debug else logging.INFO,
                        format='%(asctime)s %(levelname).1s: %(message)s',
                        datefmt='%m-%d %H:%M:%S')

    if config.gen_key:
        return print('A fresh random key:', base64.b64encode(os.urandom(16)).decode())

    if config.server:
        from wstan.server import main
    else:
        from wstan.client import main
    return main()
