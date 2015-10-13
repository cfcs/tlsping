open Rresult
open Bitstring

type client_operation =
| Connect
| Outgoing
| Queue
| Ack
| Status
| Fetch
| Subscribe

let opcode_of_client_operation = function
| Connect   -> "\x41"
| Outgoing  -> "\x42"
| Queue     -> "\x43"
| Ack       -> "\x44"
| Status    -> "\x45"
| Fetch     -> "\x46"
| Subscribe -> "\x47"

exception Invalid_opcode

let operation_of_opcode = function
| '\x41' -> Connect
| '\x42' -> Outgoing
| '\x43' -> Queue
| '\x44' -> Ack
| '\x45' -> Status
| '\x46' -> Fetch
| '\x47' -> Subscribe
| _      -> raise Invalid_opcode

type server_operation =
| Connect_answer
| Status_answer
| Incoming

let opcode_of_server_operation = function
| Connect_answer -> "\x61"
| Status_answer  -> "\x62"
| Incoming       -> "\x63"

let c_prepend_length_and_opcode opcode msg =
  let msg = string_of_bitstring msg in
  BITSTRING {
    1 + String.length msg : 16 : int, bigendian
  ; opcode_of_client_operation opcode : 8 : string
  ; msg : -1 : string
  } |> string_of_bitstring

let serialize_connect ping_interval (address, port) : string option =
  try Some (BITSTRING
  { ping_interval                      : 16 : int, bigendian
  ; String.(length address)            : 8  : int, bigendian
  ; address : (8 * String.length address)   : string
  ; port                               : 16 : int, bigendian
  } |> c_prepend_length_and_opcode Connect)
  with
  | Bitstring.Construct_failure _ -> None

let serialize_outgoing conn_id seq_num msg =
  (* right now we only send one message *)
  BITSTRING
  { conn_id : 32 : int, bigendian
  ; seq_num : 32 : int, bigendian (* seq_num offset *)
  ; 1       : 16 : int, bigendian (* record count *)
  ; msg     : -1 : string
  } |> c_prepend_length_and_opcode Outgoing

let unserialized_of_client_msg msg =
  let open Bitstring in
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
  (* we have the bytes we need, attempt to parse them *)
  bitmatch payload with
  | { opcode        : 8  : string,
        check(opcode = opcode_of_client_operation Connect)
    ; ping_interval : 16 : int, bigendian
    ; length        : 8  : int, bigendian
    ; address       : length * 8 : string
    ; port          : 16 : int, bigendian
    } -> `Connect (ping_interval, address, port)
  | { opcode  :  8 : string,
        check(opcode = opcode_of_client_operation Outgoing)
    ; conn_id : 32 : int, bigendian
    ; seq_num : 32 : int, bigendian
    ; count   : 16 : int, bigendian
    ; msg     : -1 : string
    } -> `Outgoing (conn_id , seq_num , count , msg)
  (* TODO handle more opcodes *)
  | { _ } -> `Invalid `Invalid_packet

let create_socket host =
  let open Lwt in
  let open Lwt_unix in
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

