# wstan
[![PyPI](https://img.shields.io/pypi/v/wstan.svg)](https://pypi.python.org/pypi/wstan)
[![PyPI](https://img.shields.io/pypi/pyversions/wstan.svg)](https://pypi.python.org/pypi/wstan)

Tunneling TCP connections in WebSocket to circumventing firewalls.
It's light and can run on some PaaS (with SSL support).

## Features
* Authentication
* Proxy support (using HTTP CONNECT; [test your proxy](http://www.websocket.org/echo.html))
* Display error message in browser (plain HTTP only)
* SOCKS v5 and HTTP(S) in the same port (HTTP proxy is slower)

WARN: Do not rely it on security when not using SSL (encryption always enabled, but is much weaker than SSH tunnel)

## Usage
```
wstan [-h] [-g] [-c | -s] [-d] [-z] [-p PORT] [-t TUN_ADDR]
      [-r TUN_PORT]
      [uri] [key]

positional arguments:
  uri                   URI of server
  key                   base64 encoded 16-byte key

optional arguments:
  -h, --help            show this help message and exit
  -g, --gen-key         generate a key and exit
  -c, --client          run as client (default, also act as SOCKS5/HTTP(S)
                        server)
  -s, --server          run as server
  -d, --debug
  -y PROXY, --proxy PROXY
                        let client use a HTTPS proxy (host:port)
  -z, --compatible      useful when server is behind WS proxy
  -p PORT, --port PORT  listen port of SOCKS5/HTTP(S) server at localhost
                        (defaults 1080)
  -t TUN_ADDR, --tun-addr TUN_ADDR
                        listen address of server, overrides URI
  -r TUN_PORT, --tun-port TUN_PORT
                        listen port of server, overrides URI
```

Example:
```sh
# generate a key using "wstan -g"
wstan ws://yourserver.com KEY -s  # server
wstan ws://yourserver.com KEY  # client
# now a proxy server is listening at localhost:1080 (at client side)
```

Example for OpenShift with SSL:
```sh
wstan wss://yours.rhcloud.com:8443 KEY -s -z -t $OPENSHIFT_PYTHON_IP -r $OPENSHIFT_PYTHON_PORT  # server
wstan wss://yours.rhcloud.com:8443 KEY -z  # client
```

## It's a reinvented wheel
* [chisel](https://github.com/jpillora/chisel)
* https://github.com/mhzed/wstunnel
* https://github.com/ffalcinelli/wstunnel
* shadowsocks-dotcloud
* [multitun](https://github.com/covertcodes/multitun) (VPN)
* etherws (VPN)
* websockify (not for circumventing FW)
* [gost](https://github.com/ginuerzh/gost/)

## Details
Goal: make active probing against server side more difficult while
still keeping low latency of connection establishment and being stateless (inspired by shadowsocks).

Limitation: can't prevent MITM attack; client can't detect fake server; replay attack detection may fail

Tech Detail:
* request frame has HMAC and timestamp (data frame has nothing), and all frames are encrypted using AES-128-CTR
* server will save encryption nonce and timestamp when receiving valid request (to detect replay attack)
* when establishing a connection, request frame will be encoded into URI (to achieve low latency)
* it assumes that a TCP client will send some data to server right after connection established, and those data will be put into request frame
* it has a connection pool
