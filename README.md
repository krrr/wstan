# wstan
Tunneling a TCP connection in WebSocket to circumventing firewalls. It's light and can run on some PaaS (with SSL support).

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
  -c, --client          run as client (default, also act as SOCKS v5 server)
  -s, --server          run as server
  -d, --debug
  -z, --compatible      usable when server is behind WS proxy
  -p PORT, --port PORT  listen port of SOCKS server at localhost (defaults
                        1080)
  -t TUN_ADDR, --tun-addr TUN_ADDR
                        listen address of server, override URI
  -r TUN_PORT, --tun-port TUN_PORT
                        listen port of server, override URI
```

## It's a reinvented wheel
* [chisel](https://github.com/jpillora/chisel)
* https://github.com/mhzed/wstunnel
* https://github.com/ffalcinelli/wstunnel
* shadowsocks-dotcloud
* [multitun](https://github.com/covertcodes/multitun) (VPN)
* etherws (VPN)
* websockify (not for circumventing FW)
