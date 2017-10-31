# tls-ping

_A daemon that sends PINGs over TLS._

# Current state of the project: UNFINISHED

### Terminology
- TLS v1.2 RFC: [TLS v1.2 protocol](https://tools.ietf.org/html/rfc5246)
- supported cipher suites: `tls-ping` is implemented for the following CipherSuites, see [TLS v1.2: CipherSuites](https://tools.ietf.org/html/rfc3268) for details
  - `TLS_DHE_RSA_AES_256_CBC_SHA`
  - `TLS_DHE_RSA_AES_256_CBC_SHA256`
- `proxy `: `tls-ping-server` running on a potentially untrusted machine (ie. VPS)
- `server`: IRC/Jabber/whatever TLS server
- `client`: `tls-ping-client` running on the local machine (ie. laptop)
- `control channel`: encrypted connection between `client` and `proxy`
- `connection id`: the numeric ID of an open connection
- `ping interval`: the interval for how often the `client` should dispatch ping messages, in seconds
- `seq_num`: the TLS record sequence number

### General outline

The user wants to stay connected to a service which requires activity within deterministic intervals.

`tls-ping` accomplishes this by running a `proxy` on an always-available untrusted machine, tunneling the end-to-end-encrypted TLS connection from the `client` to the `server`.

The `client` encrypts the deterministic PING messages ahead of time and sends them to the `proxy` over the `control channel` without revealing the encryption or MAC keys for the session.
The PING messages contain the sequence number for the record to enable the `client` to determine which PING messages have been sent by the `proxy` by examining the `PONG` replies.

The `client` reveals the TLS sequence number of each of the PING records (`seq_num`) as well as the `seq_num` for each regular data packet to enable the `proxy` to determine which PING messages will be appropriate to send at any given time. If the `proxy` receives a regular packet whose `seq_num` it has already replaced using a PING, the `proxy` must inform the `client` that it needs to resend the record under a different `seq_num` over the `control channel` and reject the record.

Incoming messages are queued for the user and must be ACK'ed before they're deleted from the queue. This enables a user to keep a reliable and consistent backlog of incoming messages.

If no `control channel` subscribing to a `connection id` is connected, the `proxy` sends a queued PING record every time `ping interval` seconds has elapsed and increments the `seq_num` counter for that `connection id`.

Depending on the implementation it is likely possible to have several `clients` connected at the same time, subscribing to the same connections and multiplexing transmitted messages. Multiplayer TLS; fun things can come out of that.

The TLS state may be kept in a file locally or encrypted and uploaded to the `proxy` if the user does not wish to keep state on their machine across sessions.
TODO think about: salt with hostname/port; + ?randomly generated that the user has to write down?; + ?key material from the private part of the certificate?; passphrase

### Threat model

The `proxy` is considered a potential adversary.

The `proxy` cannot alter incoming messages without the `client` being able to detect the alterations since it does not know the "TLS server MAC key", so the `client` will be able to reject incoming messages with an invalid MAC. The MAC'd value includes the sequence number, so it is not possible for the `proxy` to alter the order of incoming messages without invalidating the MAC for the reordered messages.

The `proxy` is able to replace records transmitted by the client with queued PINGs.
The user can prevent the `proxy` from doing so by either
- Never queuing PINGs
- Executing a renegotiation of the ephemeral session keys (and thus invalidating any queued PINGs by changing the "TLS client MAC key") before transmitting message records.
  Renegotiation must be done before transmitting messages each time PINGs have been queued.
  In this model, queueing PINGs can be thought of as "logging out," and the `client` would be required to renegotiate the ephemeral session keys every time it "logs in" in order to preserve the security property of the `proxy` being unable to replace transmitted records with PINGs.
If the `proxy` replaces an outgoing message, the server will respond with a PONG reply, alerting the user that the corresponding outgoing message record has been replaced.

The `proxy` cannot _modify_ transmitted records without invalidating the MAC (generated using the "TLS client MAC key") and thus causing the `server` to drop the connection.

The `server` can always silently drop transmitted messages, so we do not consider a malicious server as part of the scope for our threat model. End-to-end-encrypted overlay protocols like OTR may be used within the TLS connection to provide actual conversation integrity.

### Record structure details

Excerpt from [RFC 5246](https://tools.ietf.org/html/rfc5246#page-22)
```
      struct {
          ContentType type;
          ProtocolVersion version;
          uint16 length;
          select (SecurityParameters.cipher_type) {
              case stream: GenericStreamCipher;
              case block:  GenericBlockCipher;
              case aead:   GenericAEADCipher;
          } fragment;
      } TLSCiphertext;

      struct {
          opaque IV[SecurityParameters.record_iv_length];
          block-ciphered struct {
              opaque content[TLSCompressed.length];
              opaque MAC[SecurityParameters.mac_length];
              uint8 padding[GenericBlockCipher.padding_length];
              uint8 padding_length;
          };
      } GenericBlockCipher;
```
The `IV` is a random value.

The MAC is computed as follows: [(details in RFC 5246)](https://tools.ietf.org/html/rfc5246#section-6.2.3.1)

```
      MAC(MAC_write_key, seq_num +
                            TLSCompressed.type +
                            TLSCompressed.version +
                            TLSCompressed.length +
                            TLSCompressed.fragment);
```

The (`client`) `MAC_write_key` protects the integrity of the records and is known only to the `client` and the `server`, which makes the `proxy` unable to substitute the messages sent by the `client` with its own messages without invalidating the MAC and causing the TLS connection to be dropped.

TLS uses different sets of encryption and MAC keys for "client write" and "server write" operations respectively, which makes `proxy` unable to substitute incoming messages with PINGs that were queued with the `proxy`. See [RFC 5246 section 6.3](https://tools.ietf.org/html/rfc5246#section-6.3) for details.

Since the `seq_num` is not sent in cleartext, we need to continually tag records sent over the `control channel` with the associated `seq_num` to enable the `proxy` to keep track of which PINGs are invalidated by outgoing messages.

### Protocol considerations

- It is important that regular protocol messages sent by the `client` do not span across several records since the `proxy` has the capability to replace any valid record with a PING record. For IRC this means that the plaintext content of all records must end with `0x0d 0a`, as must all PINGs.

- The control channel must implement the following operations from the `client`:

  - `CONNECT` `{PING interval}` `{port}` `{address}`
    - return:
      - on success: `CONNECT_ANSWER` `{connection id}` `{port}` `{address}`
      - on failure: `CONNECT_ANSWER` `0` `{port}` `{address}`
    - action: Establish a TCP connection to the given address and port

  - `OUTGOING` `{connection id}` `{seq_num offset}` `seq_num count` `{encrypted TLS records}`
    - return: none
      - unless PINGs have already been with seq_num lower than `{seq_num offset} + {seq_num count}` in which case a `STATUS_ANSWER` for the `{connection id}` is returned
    - action: drop queued PINGs with `{seq_num}` lower than `{seq_num offset}` + `{seq_num count}`, if there are any

  - `QUEUE` `{connection id}` `{seq_num offset}` `{count seq_num}` `{PING record [offset + count-1]}` `{PING record [offset - count-2 ...]}` `{PING record [offset-count - 0]}`
    - return: `STATUS_ANSWER` for the `{connection id}`
    - action: store the PING records in the queue for the given `{connection id}`

  - `ACK` `{connection id}` `{seq_num offset}`
    - return: none
    - action: the `proxy` erases all queued PINGs up to and including `{seq_num offset}`
      - If the `{connection id}` has failed, a `{seq_num offset}` of `0` may be used to erase all `proxy` state related to `{connection id}`

  - `STATUS` `{first connection id}` `{last connection id}`
    - return: `STATUS_ANSWER` `{count of status tuples to follow}` and `[[` `{connection id}` `{PING interval}` `{port}` `{length of address}` `{address}` `{current seq_num}` `{count of queued PING records}` `]]` for each connected `{connection id}`. if a connection has failed, `seq_num = 0` is sent
    - action: none

  - `FETCH` `{connection id}` `{seq_num offset}` `{max seq_num}`
    - return: `INCOMING` `{count of queued PINGs}` `{seq_num offset}` `{seq_num count}` `{received TLS records}`

  - `SUBSCRIBE` `{connection id}`
    - return: see *action*
    - action: continually sends `INCOMING` messages for each received record for the duration of the lifetimes of either `control channel` or `{connection id}`


### Notes

This concept is not strictly tied to TLS or IRC and may, depending on the cipher suites employed, and the protocol, be used on other record-oriented encrypted transport protocols. TODO research.

______

# OCaml implementation: SOCKS4 proxy

### Description

The OCaml implementation of the `client` in this repository is implemented as a SOCKS4/SOCKS4a proxy.

The host, port, and sha256 fingerprint of the x509 (TLS) certificate of `server` are provided in the initial SOCKS request by the "actual client".

The sha256 fingerprint is configured as the "user_id" to send to the SOCKS proxy. This enables users to configure the fingerprints from within their client applications directly.
The user may also use this field to supply the file name of a PEM certificate of a CA trusted for the destination.

The control channel between `client` and `proxy` is protected by TLS using both client and server certificates, and they share a common (self-signed) CA.

The `proxy` only allows access to existing connections etablished in previous sessions using the same client certificate (multiple separate users can use the same `proxy`).

### Current status of the implementation

- Implemented operations:
  - `CONNECT`
  - `CONNECT_ANSWER`
  - `SUBSCRIBE`
  - `INCOMING`
- Partially implemented operations:
  - `OUTGOING`: Records are sent, but no `STATUS_ANSWER` response in case of `seq_num` mismatch, and no PING queue freeing
  - `QUEUE`: Records are queued and sent, but no `STATUS_ANSWER` given
- Operations not implemented:
  - `ACK`
  - `STATUS`
  - `STATUS_ANSWER`
  - `FETCH`

### Installation

#### Build

```
opam install caml4p bitstring lwt rresult x509 cmdliner hex
opam pin add socks --dev -k git 'https://github.com/cfcs/ocaml-socks#master'
opam pin add tls --dev -k git 'https://github.com/cfcs/tls#expose_engine_state'
```

#### Certificates

You will need some X509 certificates, generated using [ocaml-certify](https://github.com/yomimono/ocaml-certify) or some other tool:
- A CA ("Certificate Authority"); two files: the secret _key_ (which may be kept on offline storage) and the public _certificate_ (which is used by both `client` and `proxy`)
  - `selfsign --ca -k ca.secret.key -c ca.public.certificate my.friends.example.org`

- The client will need the CA `ca.public.certificate` (but **not** the _key_)
  - It will also need a client _certificate_ signed by the CA, and the _key_ the corresponds to this client _certificate_
    - The client makes a CSR (Certificate Signing Request):

      `csr --out client.csr -k client.secret.key client.example.org "A friend of ours"`
    - The client transfers this CSR file to the CA which signs it:

      `sign --client --cain ca.public.certificate --key ca.secret.key --csrin client.csr --out client.public.certificate`

- The proxy will need the CA _certificate_ (but **not** the _key_)
  - It will also need a server _certificate_ signed by the CA, and the _key_ that corresponds to this server _certificate_
  - The proxy makes a CSR (Certificate Signing Request):

    `csr --out proxy.csr -k proxy.secret.key proxy.example.org "One of our proxies"`

  - The proxy transfers this CSR file to the CA which signs it:

    `sign --cain ca.public.certificate --key ca.secret.key --csrin proxy.csr --out proxy.public.certificate`

- The CA transfers the resulting certificates to the respective key holders

At the end of the excercise the parties must have:

Client: `ca.public.certificate`, `client.secret.key`, `client.public.certificate`

Proxy: `ca.public.certificate`, `proxy.secret.key`, `proxy.public.certificate`

### Example usage

Proxy machine:
```
./tls_ping_server ./ca.public.certificate ./proxy.public.certificate ./proxy.secret.key
```

Client machine:
```
./tls_ping_client 127.0.0.1 ./ca.public.certificate ./client.public.certificate ./client.secret.key &
socat stdio socks4a:localhost:irc.example.org:6697,socksport=6697,socksuser=7e51d701e027bafa617c504dae989dd92a42273c3d8b6137a69b0d4741c9618f
```

