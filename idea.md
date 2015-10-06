# tls-pongd

_A daemon that responds to PINGs over TLS._

### Terminology
- TLS v1.2 RFC: [TLS v1.2 protocol](https://tools.ietf.org/html/rfc5246)
- supported cipher suites: `tls-pongd` is implemented for the following CipherSuites, see [TLS v1.2: CipherSuites](https://tools.ietf.org/html/rfc3268) for details
  - `TLS_DHE_RSA_AES_256_CBC_SHA`
  - `TLS_DHE_RSA_AES_256_CBC_SHA256`
- `proxy `: `tls-pongd`
- `server`: IRC/Jabber/whatever TLS server
- `client`: `tls-pong-client`
- `control channel`: encrypted connection between `client` and `proxy`
- `connection id`: the numeric ID of an open connection
- `pong interval`: the interval for how often the `client` should dispatch pong messages, in seconds
- `seq_num`: the TLS record sequence number

### General outline

The user wants to stay connected to a service which requires PONG messages sent over TLS at deterministic intervals and using deterministic PONG messages.

`tls-pongd` accomplishes this by running a `proxy` on an always-available untrusted machine, tunneling the end-to-end-encrypted TLS connection from the `client` to the `server`.

The `client` encrypts the deterministic PONG messages ahead of time and sends them to the `proxy` over the `control channel` without revealing the encryption or MAC keys for the session.

The `client` reveals the TLS sequence number of each of the PONG records (`seq_num`) as well as the `seq_num` for each regular data packet to enable the `proxy` to determine which PONG messages will be appropriate in a given setting. If the `proxy` receives a regular packet whose `seq_num` it has already replaced using a PONG, the `proxy` must inform the `client` that it needs to resend the record under a different `seq_num` over the `control channel` and reject the record.

Incoming messages are queued for the user and must be ACK'ed before they're deleted from the queue. This enables a user to keep a reliable and consistent backlog of incoming messages.

If no `control channel` subscribing to a `connection id` is connected, the `proxy` sends a queued PONG record every time `pong interval` seconds has elapsed and increments the `seq_num` counter for that `connection id`.

Depending on the implementation it is likely possible to have several `clients` connected at the same time, subscribing to the same connections and multiplexing transmitted messages. Multiplayer TLS; fun things can come out of that.

### Threat model

The `proxy` is considered a potential adversary.

The `proxy` cannot alter incoming messages without the `client` being able to detect them since it does not know the "TLS server MAC key", so the `client` will be able to reject incoming messages with an invalid MAC.

The `proxy` is able to replace records transmitted by the client with queued PONGs.
The user can prevent the `proxy` from doing so by either
- Never queuing PONGs
- Executing a renegotiation of the ephemeral session keys (and thus invalidating any queued PONGs by changing the "TLS client MAC key") before transmitting message records.
  Renegotiation must be done before transmitting messages each time PONGs have been queued.
  In this model, queueing PONGs can be thought of as "logging out," and the `client` would be required to renegotiate the ephemeral session keys every time it "logs in" in order to preserve the security property of the `proxy` being unable to replace transmitted records with PONGs.

The `proxy` cannot _modify_ transmitted records without invalidating the MAC (generated using the "TLS client MAC key") and thus causing the `server` to drop the connection.

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

The (`client`) `MAC_write_key` protects the integrity of the records and is known only to the `client` and the `server`, which makes the `proxy` unable to substitute the messages sent by the `client` with its own messages.

TLS uses different sets of encryption and MAC keys for "client write" and "server write" operations respectively, which makes `proxy` unable to substitute incoming messages with PONGs that were queued with the `proxy`. See [RFC 5246 section 6.3](https://tools.ietf.org/html/rfc5246#section-6.3) for details.

Since the `seq_num` is not sent in cleartext, we need to continually tag records sent over the `control channel` with the associated `seq_num` to enable the `proxy` to keep track of which PONGs are invalidated by outgoing messages.

### Protocol considerations

- It is important that regular protocol messages sent by the `client` do not span across several records since the `proxy` has the capability to replace any valid record with a PONG record. For IRC this means that the plaintext content of all records must end with `0x0d 0a`, as must all PONGs.

- The control channel must implement the following operations from the `client`:

  - `CONNECT` `{PONG interval}` `{address}` `{port}`
    - return:
      - on success: `CONNECT_ANSWER {connection id} {address} {port}`
      - on failure: `CONNECT_ERROR {address} {port}`
    - action: Establish a TCP connection to the given address and port

  - `OUTGOING` `{connection id}` `{seq_num offset}` `seq_num count` `{encrypted TLS records}`
    - return: none
      - unless PONGs have already been with seq_num lower than `{seq_num offset} + {seq_num count}` in which case a `STATUS_ANSWER` for the `{connection id}` is returned
    - action: drop PONGs with `{seq_num}` lower than `{seq_num offset} + `{seq_num count}`, if there are any

  - `QUEUE` `{connection id}` `{seq_num offset}` `{count seq_num}` `{PONG record [seq_num offset]}` `{PONG record [seq_num ...]}` `{PONG record [seq_num offset + count seq_num]}`
    - return: `STATUS_ANSWER` for the `{connection id}`
    - action: store the PONG records in the queue for the given `{connection id}`

  - `ACK` `{connection id}` `{seq_num offset}`
    - return: none
    - action: the `proxy` erases all queued PONGs up to and including `{seq_num offset}`
      - If the `{connection id}` has failed, a `{seq_num offset}` of `0` may be used to erase all `proxy` state related to `{connection id}`

  - `STATUS` `{first connection id}` `{last connection id}`
    - return: `STATUS_ANSWER` `{count of status tuples to follow}` and `[[` {connection id}` `{PONG interval}` `{address}` `{port}` `{current seq_num}` `{count of queued PONG records}` `]]` for each connected `{connection id}`. if a connection has failed, `seq_num = 0` is sent
    - action: none

  - `FETCH` `{connection id}` `{seq_num offset}` `{max seq_num}`
    - return: `INCOMING` `{count of queued PONGs}` `{seq_num offset}` `{seq_num count}` `{received TLS records}`

  - `SUBSCRIBE` `{connection id}`
    - return: see *action*
    - action: continually sends `INCOMING` messages for each received record for the duration of the lifetimes of either `control channel` or `{connection id}`


### Notes

This concept is not strictly tied to TLS and may, depending on the cipher suites employed, be used on other record-oriented encrypted transport protocols. TODO research.

