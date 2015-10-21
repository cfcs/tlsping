open Rresult
open Bitstring

type client_operation =
| Connect   (* connect to a server/port *)
| Outgoing  (* send an outgoing message (to the connected server/port) *)
| Queue     (* queue messages to be sent at the interval when inactive *)
| Incoming_ACK (* tell the server which buffered messages it may shred *)
| Status    (* status of open connections, current sequence number, etc *)
| Fetch     (* ask for specific elements in the Incoming buffer *)
| Subscribe (* subscribe to a connection (like a continuos stream of Fetch) *)

let opcode_of_client_operation = function
| Connect   -> "\x41"
| Outgoing  -> "\x42"
| Queue     -> "\x43"
| Incoming_ACK -> "\x44"
| Status    -> "\x45"
| Fetch     -> "\x46"
| Subscribe -> "\x47"

exception Invalid_opcode

let operation_of_opcode = function
| '\x41' -> Connect
| '\x42' -> Outgoing
| '\x43' -> Queue
| '\x44' -> Incoming_ACK
| '\x45' -> Status
| '\x46' -> Fetch
| '\x47' -> Subscribe
| _      -> raise Invalid_opcode

type server_operation =
| Connect_answer (* inform the client whether or not a Connect succeeded *)
| Status_answer  (* respond to a Status query *)
| Incoming       (* send a record from server->client *)
| Outgoing_ACK   (* tell the client to shred received outgoing messages *)

let opcode_of_server_operation = function
| Connect_answer -> "\x61"
| Status_answer  -> "\x62"
| Incoming       -> "\x63"
| Outgoing_ACK   -> "\x64"

let int64_max a b =
  if  1 = Int64.compare a b then a else b

let int64_min a b =
  if -1 = Int64.compare a b then a else b 

let c_prepend_length_and_opcode opcode msg =
  let msg = string_of_bitstring msg in
  BITSTRING {
    1 + String.length msg : 16 : int, bigendian, unsigned
  ; opcode_of_client_operation opcode : 8 : string
  ; msg : -1 : string
  } |> string_of_bitstring

let serialize_connect ping_interval (address, port) : string option =
  try Some (BITSTRING
  { ping_interval                      : 16 : int, bigendian
  ; port                               : 16 : int, bigendian
  ; address : (8 * String.length address)   : string
  } |> c_prepend_length_and_opcode Connect)
  with
  | Bitstring.Construct_failure _ -> None

let serialize_outgoing conn_id seq_num msg =
  (* right now we only send one message *)
  BITSTRING
  { conn_id : 32 : int, unsigned, bigendian
  ; seq_num : 64 : int, unsigned, bigendian (* seq_num offset *)
  ; 1       : 16 : int, unsigned, bigendian (* record count *)
  ; msg     : -1 : string
  } |> c_prepend_length_and_opcode Outgoing

let serialize_queue ~conn_id seq_num msgs =
  let rec s_msg acc = function
  | msg :: tl ->
      s_msg
      ((BITSTRING
        { String.length msg : 16 : int, unsigned, bigendian
        ; msg : -1 : string } |> string_of_bitstring)
      :: acc) tl
  | [] -> String.concat "" acc
  in
  BITSTRING
  { conn_id       : 32 : int, unsigned, bigendian
  ; seq_num       : 64 : int, unsigned, bigendian
  ; s_msg [] msgs : -1 : string
  } |> c_prepend_length_and_opcode Queue

let serialize_subscribe conn_id =
  BITSTRING
  { conn_id : 32 : int, unsigned, bigendian
  } |> c_prepend_length_and_opcode Subscribe

type connection_status =
  { conn_id : int32
  ; ping_interval : int
  ; address : string
  ; port : int
  ; seq_num : int64
  ; queue_length : int32
  }

let s_prepend_length_and_opcode opcode msg =
  let msg = string_of_bitstring msg in
  BITSTRING {
    1 + String.length msg             : 16 : int, bigendian, unsigned
  ; opcode_of_server_operation opcode :  8 : string
  ; msg : -1 : string
  } |> string_of_bitstring

let serialize_status_answer connections =
  let rec serialize (acc : bytes list)= function
  | { conn_id ; ping_interval ; address ; port ; seq_num ; queue_length } :: tl ->
      serialize (string_of_bitstring (BITSTRING
      { conn_id       : 32 : int, unsigned, bigendian
      ; ping_interval : 16 : int, unsigned, bigendian
      ; port          : 16 : int, unsigned, bigendian
      ; String.length address :  8 : int, unsigned, bigendian
      ; address       : -1 : string
      ; seq_num       : 64 : int, unsigned, bigendian
      ; queue_length  : 32 : int, unsigned, bigendian (* amount of PINGs queued *)
      }) :: acc) tl
  | [] -> Bytes.concat "" acc
          |> bitstring_of_string |> s_prepend_length_and_opcode Status_answer
  in serialize connections

let serialize_incoming conn_id next_seq_num queued_seq_num msg =
  BITSTRING {
     conn_id        : 32 : int, unsigned, bigendian
  ;  next_seq_num   : 64 : int, unsigned, bigendian
  ;  queued_seq_num : 64 : int, unsigned, bigendian
  ;  msg : -1 : string
  } |> s_prepend_length_and_opcode Incoming

let serialize_connect_answer conn_id address port =
  BITSTRING
  { conn_id  : 32 : int, unsigned, bigendian
  ; port     : 16 : int, unsigned, bigendian
  ; address  : -1 : string
  } |> s_prepend_length_and_opcode Connect_answer

let serialize_outgoing_ack (conn_id : int32) status seq_num next_seq_num =
  let status =
    match status with
    | `Ok     -> 0
    | `Resend -> 1
  in
  BITSTRING
  { conn_id      : 32 : int, unsigned, bigendian
  ; status       :  8 : int, unsigned, bigendian
  ; seq_num      : 64 : int, unsigned, bigendian
  ; next_seq_num : 64 : int, unsigned, bigendian
  } |> s_prepend_length_and_opcode Outgoing_ACK

let read_msg_len msg =
  let msg_len = String.length msg in
  if 2 > msg_len then `Need_more (2 - msg_len)
  else
  let length , payload, payload_len =
    (bitmatch bitstring_of_string msg with
    { length  : 16 : int, bigendian
    ; payload : -1 : bitstring } -> length , payload, bitstring_length payload / 8)
  in
  if length > payload_len
  then `Need_more (length - payload_len)
  else if length < payload_len
  then `Invalid `Too_long (* should never happen *)
  else
    `Payload payload

let unserialized_of_client_msg msg =
  (* parses CONNECT ; OUTGOING ; QUEUE ; ACK ; STATUS ; FETCH ; SUBSCRIBE *)
  match read_msg_len msg with
  | (`Need_more _ | `Invalid _) as ret -> ret
  | `Payload payload ->
  (* we have the bytes we need, attempt to parse them *)
  bitmatch payload with

  | { opcode        :  8 : string,
        check(opcode = opcode_of_client_operation Connect)
    ; ping_interval : 16 : int, unsigned, bigendian
    ; port          : 16 : int, unsigned, bigendian
    ; address       : -1 : string
    } -> `Connect (ping_interval, address, port)

  | { opcode  :  8 : string,
        check(opcode = opcode_of_client_operation Outgoing)
    ; conn_id : 32 : int, unsigned, bigendian, check(conn_id <> 0l)
    ; seq_num : 64 : int, unsigned, bigendian
    ; count   : 16 : int, unsigned, bigendian (* amount of TLS records in msg *)
    ; msg     : -1 : string
    } -> `Outgoing (conn_id , seq_num , count , msg)

  | { opcode  :  8 : string,
        check(opcode = opcode_of_client_operation Queue)
    ; conn_id : 32 : int, unsigned, bigendian, check(conn_id <> 0l)
    ; seq_num : 64 : int, unsigned, bigendian
    ; msgs    : -1 : bitstring
    } ->
      let rec unpack_msgs acc msgs = (
        bitmatch msgs with
        | { len :  16 : int, unsigned, bigendian, check(len <> 0), bind(len*8)
          ; msg : len : string
          ; tl  :  -1 : bitstring
          } -> unpack_msgs (msg :: acc) tl
        | { _ } as x when 0 = bitstring_length x ->
            `Queue (conn_id , seq_num , acc) (*TODO tag each?*)
        | { _ } ->
            `Invalid `Invalid_packet
      )in
      unpack_msgs [] msgs

  | { opcode  :  8 : string,
        check(opcode = opcode_of_client_operation Subscribe)
    ; conn_id : 32 : int, unsigned, bigendian, check(conn_id <> 0l)
    } -> `Subscribe conn_id

  (* TODO handle more opcodes *)
  | { _ } -> `Invalid `Invalid_packet

let unserialized_of_server_msg msg =
  (* parses CONNECT_ANSWER ; INCOMING ; STATUS_ANSWER *)
  match read_msg_len msg with
  | (`Need_more _ | `Invalid _) as ret -> ret
  | `Payload payload ->
  bitmatch payload with

  | { opcode   :  8 : string,
        check(opcode = opcode_of_server_operation Connect_answer)
    ; conn_id  : 32 : int, unsigned, bigendian
    ; port     : 16 : int, unsigned, bigendian
    ; address  : -1 : string
    } -> `Connect_answer (conn_id , address, port)

  | { opcode :  8 : string,
        check(opcode = opcode_of_server_operation Incoming)
    ; conn_id        : 32 : int, unsigned, bigendian
    ; next_seq_num   : 64 : int, unsigned, bigendian
    ; queued_seq_num : 64 : int, unsigned, bigendian
    ; msg    : -1 : string
    } -> `Incoming (conn_id , next_seq_num , queued_seq_num , msg)

  | { opcode   :  8 : string,
        check(opcode = opcode_of_server_operation Outgoing_ACK)
    ; conn_id  : 32 : int, unsigned, bigendian, check(conn_id <> 0l)
    ; status   :  8 : int, unsigned, bigendian,
        check(0 <= status && status <= 1)
    ; seq      : 64 : int, unsigned, bigendian
    ; next_seq : 64 : int, unsigned, bigendian
    } ->
      let status =
        begin match status with
        | 0 -> `Ok
        | 1 -> `Resend
        | _ -> failwith "TODO should never happen" end
      in `Outgoing_ACK (conn_id , status , seq , next_seq)

  | { opcode :  8 : string,
        check(opcode = opcode_of_server_operation Status_answer)
    ; tuples : -1 : bitstring
    } ->
      let rec parse_tuples tuples acc =
        if 0 = Bitstring.bitstring_length tuples then
          `Status_answer acc
        else
        (bitmatch Bitstring.takebits (32 + 16 + 8) tuples with
        | { conn_id       : 32 : int, unsigned, bigendian
          ; ping_interval : 16 : int, unsigned, bigendian
          ; port          : 16 : int, unsigned, bigendian
          ; addr_len      :  8 : int, unsigned, bigendian, bind(addr_len * 8)
          } as header ->
            (bitmatch Bitstring.takebits (addr_len + 16 +32 + 32) tuples with
            | { address      : addr_len : string
              ; seq_num      : 64 : int, unsigned, bigendian
              ; count_queued : 32 : int, unsigned, bigendian (* amount of PINGs queued *)
              } as body ->
                parse_tuples
                (takebits (bitstring_length header + bitstring_length body) tuples)
                 @@ (conn_id , ping_interval, address, port, seq_num, count_queued) :: acc
            | { _ } -> `Invalid `Invalid_packet
            )
        | { _ } -> `Invalid `Invalid_packet
        )
      in
      parse_tuples tuples []

  | { _ } -> `Invalid `Invalid_packet

let create_socket host =
  let open Lwt in
  let open Lwt_unix in
  (* TODO handle try gethostbyname with | Not_found *)
  Lwt_unix.gethostbyname host >>= fun host_entry ->
  if 0 = Array.length host_entry.h_addr_list then
    return @@ R.error ()
  else
    let host_inet_addr = host_entry.h_addr_list.(0) in
    let s = Lwt_unix.socket host_entry.h_addrtype SOCK_STREAM 0 in
    return @@ R.ok (s , host_inet_addr)

type tls_config = {
  authenticator : X509.Authenticator.a
; ciphers : Tls.Ciphersuite.ciphersuite list
; version : Tls.Core.tls_version * Tls.Core.tls_version
; hashes  : Nocrypto.Hash.hash list
; certificates : Tls.Config.own_cert
}

let tls_config (ca_public_cert , public_cert , secret_key) =
  let open Lwt in
  X509_lwt.authenticator (`Ca_file ca_public_cert) >>= fun authenticator ->
  X509_lwt.private_of_pems ~cert:public_cert ~priv_key:secret_key >>= fun cert ->
  return {
    authenticator
  ; ciphers = [`TLS_DHE_RSA_WITH_AES_256_CBC_SHA256]
  ; version = Tls.Core.(TLS_1_2,TLS_1_2)
  ; hashes  = [`SHA256]
  ; certificates = (`Single cert)
  }

