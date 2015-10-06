=== Terminology
- TLS v1.2 RFC: [TLS v1.2 protocol](https://tools.ietf.org/html/rfc5246)
- supported cipher suites: `tls-pongd` is implemented for the following CipherSuites, see [TLS v1.2: CipherSuites](https://tools.ietf.org/html/rfc3268) for details
  - `TLS_DHE_RSA_AES_256_CBC_SHA`
  - `TLS_DHE_RSA_AES_256_CBC_SHA256`
- `proxy `: `tls-pongd`
- `server`: IRC/Jabber/whatever TLS server
- `client`: `tls-pong-client`
- `control channel`: encrypted connection between `client` and `proxy`
- `connection id`: the numeric ID of an open connection
- `pong interval`: the interval for how often the `client` should dispatch pong messages

=== General outline
The user wants to stay connected to a service which requires PONG messages sent over TLS at deterministic intervals and using deterministic PONG messages.

`tls-pongd` accomplishes this by running a `proxy` on an always-available untrusted machine, tunneling the end-to-end-encrypted TLS connection from the `client` to the `server`.

The `client` encrypts the deterministic PONG messages ahead of time and sends them to the `proxy` over the `control channel` without revealing the encryption or MAC keys for the session.

The `client` reveals the TLS sequence number of each of the PONG records (`seq_num`) as well as the `seq_num` for each regular data packet to enable the `proxy` to determine which PONG messages will be appropriate in a given setting. If the `proxy` receives a regular packet whose `seq_num` it has already replaced using a PONG, the `proxy` must inform the `client` that it needs to resend the record under a different `seq_num` over the `control channel` and reject the record.

=== Record structure details
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

The `MAC_write_key` protects the integrity of the records and is known only to the `client`, which makes the `proxy` unable to substitute the messages sent by the `client` with its own messages.

=== Protocol considerations
- It is important that regular protocol messages sent by the `client` do not span across several records since the `proxy` has the capability to replace any valid record with a PONG record. For IRC this means that the plaintext content of all records must end with `0x0d 0a`, as must all PONGs.

- The control channel must implement the following operations:
  - `CONNECT` `{address}` `{port}`
    - returns `CONNECT_ANSWER {connection id}`

  - `OUTGOING` `{connection id}` `{seq_num offset}` `seq_num count` `{encrypted TLS records}`
    - no return value

  - `QUEUE` `{connection id}` `{seq_num offset}` `{count seq_num}` `{PONG record [seq_num offset]}` `{PONG record [seq_num ...]}` `{PONG record [seq_num offset + count seq_num]}`
    - return TODO

  - `STATUS` `{first connection id}` `{last connection id}`
    - returns `STATUS_ANSWER` `{count of status tuples to follow}` and `[[` {connection id}` `{address}` `{port}` `{current seq_num}` `{count of queued PONG records}` `]]` for each connected `{connection id}`. if a connection has failed, `seq_num = 0` is sent

  - `FETCH` `{connection id}` `{seq_num offset}` `{max seq_num}`
    - `INCOMING` `{seq_num offset}` `{seq_num count}` `{received TLS records}`

  - `SUBSCRIBE` `{connection id}`
    - continually sends `INCOMING` messages for each received record

