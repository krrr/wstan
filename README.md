# wstan
[![PyPI](https://img.shields.io/pypi/v/wstan.svg)](https://pypi.python.org/pypi/wstan)
[![PyPI](https://img.shields.io/pypi/pyversions/wstan.svg)](https://pypi.python.org/pypi/wstan)

Tunneling TCP connections in WebSocket to circumvent firewall.
It's light and can run on some PaaS (SSL supported).

`User-Agent(SOCKS/HTTP) <--> (wstan)Client <-- Internet --> (wstan)Server <--> Target`

## Features
* Encryption
* Proxy support (using HTTP CONNECT; [test yours](http://www.websocket.org/echo.html))
* Display error message in browser (plain HTTP only)
* SOCKSv4/v5 and HTTP (slower) in the same port

WARN: Do not rely it on security when not using SSL

## Usage
```
usage: wstan [-h] [-g] [-c | -s] [-d] [-z] [-i INI] [-y PROXY] [-a ADDR] [-p PORT] [--pool-size POOL_SIZE]
             [--pool-max-idle POOL_MAX_IDLE] [-t TUN_ADDR] [-r TUN_PORT] [--x-forward]
             [uri] [key]

positional arguments:
  uri                   URI of server
  key                   password or generated key

options:
  -h, --help            show this help message and exit
  -g, --gen-key         generate a 16 byte base64 key and exit
  -c, --client          run as client (default, also act as SOCKS/HTTP server)
  -s, --server          run as server
  -d, --debug
  -z, --compatible      useful when server is behind WS proxy
  -i INI, --ini INI     load config file

client options:
  -y PROXY, --proxy PROXY
                        use HTTP proxy to connect to wstan server (host:port)
  -a ADDR, --addr ADDR  listen address of SOCKS/HTTP server (defaults localhost)
  -p PORT, --port PORT  listen port of SOCKS/HTTP server (defaults 1080)
  --pool-size POOL_SIZE
                        max size of connection pool (defaults 16)
  --pool-max-idle POOL_MAX_IDLE
                        max idle timeout of connection pool in sec (defaults 300)

server options:
  -t TUN_ADDR, --tun-addr TUN_ADDR
                        listen address of server, overrides URI
  -r TUN_PORT, --tun-port TUN_PORT
                        listen port of server, overrides URI
  --x-forward           use X-Forwarded-For as client IP address when behind proxy
```

#### Setup:
```sh
# generate a key using "wstan -g"
wstan ws://yourserver.com KEY -s  # server
wstan ws://yourserver.com KEY  # client
# a proxy server is listening at localhost:1080 now (at client side)
```

#### Setup for OpenShift v3:
1. [Generate a key](http://rextester.com/TZXL63621)
2. Pull [Docker image](https://hub.docker.com/r/krrr/wstan/) and set environment variable `KEY`
3. Add default route
4. `http://xxx.openshiftapps.com` will return 200 if everything goes right; Run client `wstan ws://xxx.openshiftapps.com KEY`

## It's a reinvented wheel
* [chisel](https://github.com/jpillora/chisel)
* https://github.com/mhzed/wstunnel
* https://github.com/ffalcinelli/wstunnel
* shadowsocks-dotcloud
* [multitun](https://github.com/covertcodes/multitun) (VPN)
* etherws (VPN)
* websockify (not for circumventing FW)
* [gost](https://github.com/ginuerzh/gost/)
* [v2ray](https://www.v2ray.com)

## Details
Original Goal: make active probing against server side more difficult while
still keeping low latency of connection establishment and being stateless (inspired by shadowsocks).

Weakness: can't prevent MITM attack; client can't detect fake server (may receive garbage data);
replay attack detection may fail

Tech Detail:
* request frame has HMAC and timestamp (data frame has nothing), and all frames are encrypted using AES-128-CTR
* server will save encryption nonce and timestamp when receiving valid request (to detect replay attack)
* the first request frame will be encoded into URI of WS handshake (to achieve low latency)
* it has a connection pool
