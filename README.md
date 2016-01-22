# wstan
Tunneling a TCP connection in WebSocket to circumventing firewalls.
It's light and can run on some PaaS (with SSL support).

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
  -z, --compatible      usable when server is behind WS proxy
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

An experiment that try to make active probing against server side harder while
still keeping low latency (of connection establishment). It's stateless
and act as a SOCKS v5 server at localhost (like shadowsocks). TCP-fastopen
not supported yet, but a connection pool may help you a little.

WARN: Do not rely it on security

