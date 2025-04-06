wstan protocol is based on WebSocket, and every WS message is binary.

`User-Agent <--SOCKS/HTTP--> (wstan)Client <--this protocol--> (wstan)Server <---> Target`

_the protocol uses network byte order (big-endian)_

### Encryption
All WS messages are encrypted using AES-128-CTR when SSL disabled. The key is pre-shared and also used by HMAC.

Nonce (16bytes) used to encrypt will be generated and exchanged by following ways:
* Default
  * **client**: randomly generated; passed to server by `Sec-WebSocket-Key` field of WS handshake request
  * **server**: calculated from `Sec-WebSocket-Key`, equals `Sec-WebSocket-Accept` field of WS handshake reply (leftmost 16 bytes, [detail](https://en.wikipedia.org/wiki/WebSocket#Protocol_handshake)); no exchange
* Compatible mode
  * **client**: randomly generated; passed to server by `Cookie` field that contains one pair: the first is underscore plus `(last_byte_of_sha1_of_key % 26) + 65)`(e.g. `_A`), and the last is base64 encoded nonce.
  * **server**: leftmost 16 bytes of SHA1 of the encryptor nonce used by client; no exchange

### Commands
| Command | Enum | Meaning                                                 |
|---------|------|---------------------------------------------------------|
| CMD_REQ | 0x00 | request to connect to a target using TCP and relay data |
| CMD_DAT | 0x01 | carries TCP data                                        |
| CMD_RST | 0x02 | reset tunnel, make it able to accept another request    |
| CMD_DGM | 0x03 | carries UDP packet                                      |

### Messages
* **Request message**:

   |   Field   | Length(Bytes) | Detail                                              |
   |:---------:|:-------------:|-----------------------------------------------------|
   |   type    |       1       | CMD_REQ for TCP, CMD_DGM for UDP                    |
   | timestamp |       8       | seconds since epoch (the double type of C language) |
   |  address  |     var.      | address of target. ADDRESS structure                |
   |   data    |     var.      | to be sent to target                                |
   |   HMAC    |      10       | hmac-sha1 of previous parts (leftmost 10 bytes)     |

    Request message may be encoded into URI of WS handshake (`http://a.a/encoded-req`; encoding using url-safe base64 (substitutes `-` instead of `+` and `_` instead of `/` in the standard base64 alphabet)). Server should check timestamp and deny expired request (default timeout is 60s). Server may also remember accepted requests and deny reused nonce.

* **Data message**:

   | Field | Length(Bytes) | Detail                             |
   |:-----:|:-------------:|------------------------------------|
   | type  |       1       | CMD_DAT                            |
   | data  |     var.      | to be sent to target or user-agent |

    There is no multiplexing. Once a request is accepted the tunnel (and underlying TCP conn.) will be exclusively used by it.

* **Reset message**:

   | Field  | Length(Bytes) | Detail                                                 |
   |:------:|:-------------:|--------------------------------------------------------|
   |  type  |       1       | CMD_RST                                                |
   | reason |     var.      | UTF-8 encoded string; ignored if started with 2 spaces |
   |  HMAC  |      10       | hmac-sha1 of previous parts (leftmost 10 bytes)        |

    Server can tell client why request is failed using `reason` field. A normal reset's `reason` should only contain spaces.
 
* **Datagram message**:

   |    Field    | Length(Bytes) | Detail                                                                           |
   |:-----------:|:-------------:|----------------------------------------------------------------------------------|
   |    type     |       1       | CMD_DGM                                                                          |
   |   address   |     var.      | address of opposite end. ADDRESS structure                                       |
   |    data     |     var.      | to be sent to target or user-agent                                               |

* **Close message**: Using close message of WebSocket directly.

### Common Structures
* **ADDRESS structure**:

    |     Field      | Length(Bytes) | Detail                                                                                          |
    |:--------------:|:-------------:|-------------------------------------------------------------------------------------------------|
    |    RESERVED    |       1       | must be 0x00                                                                                    |
    |  address type  |       1       | 0x01=IPv4; 0x03=Domain name; 0x04=IPv6                                                          |
    | target address |     var.      | 4 bytes for IPv4; 1 byte of name length followed by the name for domain name; 16 bytes for IPv6 |
    |  port number   |       2       |                                                                                                 |

    Is the same as a part of SOCKS5 request
 
### States of tunnel
* --> **IDLE**(initial)
* **IDLE** --REQ-received--> **USING**
* **USING** --RST-sent--> **RESETTING** --RST-received--> **IDLE**
* **USING** --RST-received--> **IDLE**  (a RST will be sent immediately as reply)

