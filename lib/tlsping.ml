open Rresult

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

let server_operation_of_opcode = function
  | '\x61' -> Connect_answer
  | '\x62' -> Status_answer
  | '\x63' -> Incoming
  | '\x64' -> Outgoing_ACK
  | _ -> raise Invalid_opcode

let int64_max a b =
  if  1 = Int64.compare a b then a else b

let int64_min a b =
  if -1 = Int64.compare a b then a else b

let leX_of_int (type i) ~x ~(shift:i -> int -> int) (v:i) = String.init x
    (fun i -> char_of_int ((shift v (i*8)) land 0xff))

let le8 v = String.make 1 (char_of_int v)
let le16 v = leX_of_int ~x:2 ~shift:(fun i v -> i lsr v) v
let le32 v = leX_of_int ~x:4
    ~shift:(fun i v -> Int32.(shift_right i v |> to_int)) v
let le64 v = leX_of_int ~x:8
    ~shift:(fun i v -> Int64.(shift_right i v |> to_int)) v
let le16len msg = le16 (String.length msg) ^ msg
let ofle8 ?(off=0) s = int_of_char s.[off]
let ofle16 ?(off=0) s = (int_of_char s.[off+1] lsl 8) + (int_of_char s.[off+0])
let ofle32 ?(off=0) s =
  String.to_seq (String.sub s off 4) |> List.of_seq |> List.rev
  |> List.fold_left
    Int32.(fun acc c -> add (shift_left acc 8) (of_int @@ int_of_char c)) 0l
let ofle64 ?(off=0) s =
  String.to_seq (String.sub s off 4) |> List.of_seq |> List.rev
  |> List.fold_left
    Int64.(fun acc c -> add (shift_left acc 8) (of_int @@ int_of_char c)) 0L


let c_prepend_length_and_opcode opcode msg =
  let len = 1 + String.length msg in
  let op = opcode_of_client_operation opcode in
  (le16 len) ^ op ^ msg

let serialize_connect ping_interval (address, port) : string option =
  Some ((le16 ping_interval
         ^ le16 port
         ^ address)
        |> c_prepend_length_and_opcode Connect)

let serialize_outgoing conn_id seq_num msg =
  (* right now we only send one message *)
  (le32 conn_id
  ^le64 seq_num (* seq_num offset *)
  ^le16 1 (* record count *)
  ^msg
 ) |> c_prepend_length_and_opcode Outgoing

let serialize_queue ~conn_id seq_num (msgs : string list) : string list =
  (* splits a list of PINGs into a number of serialized QUEUE
   * messages, wrapping at 65535 bytes**)
  let fst a  = let (t , _, _, _) = a in t in
  let snd a  = let (_ , t, _, _) = a in t in
  let thrd a = let (_ , _, t, _) = a in t in
  let frth a = let (_ , _, _, t) = a in t in
  let msgs =
  List.rev @@
  List.fold_right
  (*TODO this should be a fold_left to avoid the List.rev *)
  ( fun msg -> function
    | (acc_hd :: acc_tl) ->
    let acc_len = fst acc_hd in
    let msg = le16len msg in
    let msg_len = String.(length msg) in
    (* check if the msg + (32+64)/8=12 (conn_id and seq_num offset)
     * -(16+8)/8=3 (length and opcode) will overflow the 16 bit length
     * and wrap it into separate QUEUE messages accordingly: *)
    if (1 lsl 16) - 12 - 3 > acc_len + msg_len then
      ((acc_len + msg_len , msg::(snd acc_hd)
        , thrd acc_hd , Int64.succ @@ frth acc_hd
      ):: acc_tl)
    else
      (* the msg would overflow, so make a new QUEUE msg: *)
      let new_seq = frth acc_hd in
      ((msg_len , [msg] , new_seq , new_seq
      ) :: acc_hd :: acc_tl)
    | [] as empty -> empty
  ) List.(rev msgs) [(0, [], seq_num, seq_num)]
  in
  List.(fold_right
  (fun lst -> fun acc ->
     ((
       le32 conn_id
       ^ le64 (thrd lst)
       ^ String.concat "" (snd lst)
     ) |> c_prepend_length_and_opcode Queue)
     :: acc
  ) msgs [])

(*TODO serialize_incoming_ack *)

let serialize_status first_conn_id last_conn_id =
  Logs.debug (fun m -> m "%s first_conn_id:%ld last_conn_id:%ld"
                 __LOC__ first_conn_id last_conn_id);
  (le32 first_conn_id
   ^ le32 last_conn_id
  ) |> c_prepend_length_and_opcode Status

(*TODO serialize_fetch *)

let serialize_subscribe conn_id =
  le32 conn_id
  |> c_prepend_length_and_opcode Subscribe

type connection_status =
  { conn_id : int32
  ; ping_interval : int
  ; address : string
  ; port : int
  ; seq_num : int64
  ; queue_length : int32
  }

let s_prepend_length_and_opcode opcode msg =
  le16 (1 + String.length msg)
  ^ opcode_of_server_operation opcode
  ^ msg

let serialize_status_answer connections =
  let rec serialize (acc : string list) = function
    | { conn_id ; ping_interval ; address ; port ; seq_num ;
        queue_length } :: tl ->
      serialize ((
          String.concat "" [
            le32 conn_id
          ; le16 ping_interval
          ; le16 port
          ; le8 (String.length address)
          ; address
          ; le64 seq_num
          ; le32 queue_length (* amount of PINGs queued *)
          ]
        ) :: acc) tl
    | [] -> String.concat "" acc
            |> s_prepend_length_and_opcode Status_answer
  in serialize [] connections

let serialize_incoming conn_id next_seq_num queued_seq_num msg =
 String.concat "" [
   le32 conn_id
  ; le64 next_seq_num
  ; le64 queued_seq_num
  ; msg
  ] |> s_prepend_length_and_opcode Incoming

let serialize_connect_answer conn_id address port =
  String.concat "" [
    le32 conn_id
  ; le16 port
  ; address
  ] |> s_prepend_length_and_opcode Connect_answer

let serialize_outgoing_ack (conn_id : int32) status seq_num next_seq_num =
  let status =
    match status with
    | `Ok     -> 0
    | `Resend -> 1
  in
  String.concat ""
  [ le32 conn_id
  ; le8 status
  ; le64 seq_num
  ; le64 next_seq_num
  ] |> s_prepend_length_and_opcode Outgoing_ACK

let read_msg_len msg =
  let msg_len = String.length msg in
  if 2 > msg_len then `Need_more (2 - msg_len)
  else
    let length , payload, payload_len =
      let payload = String.sub msg 2 (String.length msg - 2) in
      (int_of_char msg.[1] lsl 8) + (int_of_char msg.[0]),
      payload, String.length payload
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
    match operation_of_opcode payload.[0] with
    | Connect ->
      let ping_interval = ofle16 ~off:1 payload in
      let port = ofle16 ~off:3 payload in
      let address = String.sub payload 5 (String.length payload -5) in
      `Connect (ping_interval, address, port)

    | Outgoing ->
      let conn_id = ofle32 ~off:1 payload in
      assert (conn_id <> 0l);
      let seq_num = ofle64 ~off:5 payload in
      let count =
        ofle16 ~off:(1+4+8) payload in (* amount of TLS records in msg *)
      let msg = String.sub payload (1+4+8+2) (String.length payload -1-4-8-2) in
      `Outgoing (conn_id , seq_num , count , msg)

  | Queue ->
    let conn_id = ofle32 ~off:1 payload in
    assert (conn_id <> 0l);
    let seq_num = ofle64 ~off:(1+4) payload in
    let rec unpack_msgs acc msgs = (
      match msgs with
      | "" -> `Queue (conn_id , seq_num , acc) (*TODO tag each?*)
      | _ ->
      try begin let len = ofle16 msgs in
      assert (len <> 0);
      let msg = String.sub msgs 2 len in
      let tl = String.sub msgs (2+len) (String.length msgs-2-len) in
      unpack_msgs (msg :: acc) tl
      end
      with
      | _ -> `Invalid `Invalid_packet
    ) in
    let msgs = String.sub payload (1+4+8) (String.length payload-1-4-8) in
    unpack_msgs [] msgs

  (*TODO handle Incoming_ack *)

  | Status ->
    let first_conn_id = ofle32 ~off:1 payload in
    let last_conn_id = ofle32 ~off:(1+4) payload in
    if first_conn_id > last_conn_id then
      Logs.err (fun m -> m "first_conn_id:%ld last_conn_id:%ld"
                  first_conn_id last_conn_id);
    assert (first_conn_id <= last_conn_id);
    `Status (first_conn_id , last_conn_id)

  (*TODO handle fetch *)

  | Subscribe ->
    let  conn_id = ofle32 ~off:1 payload in
    assert (conn_id <> 0l);
    `Subscribe conn_id

  (* TODO handle more opcodes *)
  | _ -> `Invalid `Invalid_packet

let unserialized_of_server_msg msg =
  (* parses CONNECT_ANSWER ; INCOMING ; STATUS_ANSWER *)
  match read_msg_len msg with
  | (`Need_more _ | `Invalid _) as ret -> ret
  | `Payload payload ->
  try (match server_operation_of_opcode payload.[0] with
  | Connect_answer ->
    let conn_id = ofle32 ~off:1 payload in
    let port = ofle16 ~off:(1+4) payload in
    let address = String.sub payload (1+4+2) (String.length payload-1-4-2) in
    `Connect_answer (conn_id , address, port)

  | Incoming ->
    let conn_id = ofle32 ~off:1 payload in
    let next_seq_num = ofle64 ~off:(1+4) payload in
    let queued_seq_num = ofle64 ~off:(1+4+8) payload in
    let msg = String.sub payload (1+4+8+8) (String.length payload -1-4-8-8) in
    `Incoming (conn_id , next_seq_num , queued_seq_num , msg)

  | Outgoing_ACK ->
    let conn_id = ofle32 ~off:1 payload in
    assert (conn_id <> 0l);
    let status = ofle8 ~off:(1+4) payload in
    assert (0 <= status && status <= 1);
    let seq = ofle64 ~off:(1+4+1) payload in
    let next_seq = ofle64 ~off:(1+4+1+8) payload in
    let status =
      begin match status with
        | 0 -> `Ok
        | 1 -> `Resend
        | _ -> failwith "TODO should never happen" end
    in `Outgoing_ACK (conn_id , status , seq , next_seq)

  | Status_answer ->
    let rec parse_tuples tuples acc =
      if 0 = String.length tuples then
        `Status_answer acc
      else
        try (
          let conn_id = ofle32 tuples in
          let ping_interval = ofle16 ~off:4 tuples in (* in seconds *)
          let port = ofle16 ~off:6 tuples in
          let addr_len = ofle8 ~off:8 tuples in
          let address = String.sub tuples 9 (addr_len) in
          let seq_num = ofle64 ~off:(9+addr_len) tuples in
          (* next write seq_num expected by the destination *)

          let count_queued = ofle32 ~off:(9+addr_len+8) tuples in
          (* amount of PINGs queued *)
          let tail = String.sub tuples (9+addr_len+8+4)
              (String.length tuples-9-addr_len-8-4) in
          parse_tuples
            (tail)
          @@ (conn_id , ping_interval, address, port,
              seq_num, count_queued) :: acc
        ) with
        | _ -> `Invalid `Invalid_status_answer
      in
      parse_tuples (String.sub payload 1 (String.length payload-1)) []

  ) with | _ -> `Invalid `Invalid_packet

let create_socket host =
  let open Lwt in
  let open Lwt_unix in
  (* TODO handle try gethostbyname with | Not_found *)
  Lwt_unix.gethostbyname host >>= fun host_entry ->
  if [| |] = host_entry.h_addr_list then
    return @@ R.error ()
  else
    let host_inet_addr = host_entry.h_addr_list.(0) in
    let s = Lwt_unix.socket host_entry.h_addrtype SOCK_STREAM 0 in
    return @@ R.ok (s , host_inet_addr)

type tls_config = {
  authenticator : X509.Authenticator.t
; ciphers : Tls.Ciphersuite.ciphersuite list
; version : Tls.Core.tls_version * Tls.Core.tls_version
; hashes  : Nocrypto.Hash.hash list
; certificates : Tls.Config.own_cert
}

let tls_config (ca_public_cert , public_cert , secret_key) =
  let open Lwt in
  X509_lwt.authenticator (`Ca_file ca_public_cert) >>= fun authenticator ->
  X509_lwt.private_of_pems ~cert:public_cert
    ~priv_key:secret_key >>= fun cert ->
  return {
    authenticator
  ; ciphers = [`TLS_DHE_RSA_WITH_AES_256_CBC_SHA256]
  ; version = Tls.Core.(TLS_1_2,TLS_1_2)
  ; hashes  = [`SHA256]
  ; certificates = (`Single cert)
  }
