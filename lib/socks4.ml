(* SOCKS4 / SOCKS4a 

http://ftp.icm.edu.pl/packages/socks/socks4/SOCKS4.protocol

https://en.wikipedia.org/wiki/SOCKS#SOCKS4a
*)
open Rresult

type socks4_request =
  { port    : int
  ; address : string
  ; username : string }

let socks_request ~username hostname port =
  String.concat ""
    [ (* field 1: SOCKS version *)
    "\x04"
      (* field 2: command code: "connect stream": *)
    ; "\x01"
      (* field 3: bigendian port: *)
    ; (port land 0xff00) lsr 8 |> char_of_int |> String.make 1
    ;  port land 0xff          |> char_of_int |> String.make 1
      (* field 4: invalid ip: *)
    ; "\x00\x00\x00\xff"
      (* field 5: user ID string followed by terminator: *)
    ; username ; "\x00"
      (* field 6: hostname string followed by terminator: *)
    ; hostname ; "\x00"
    ]

let socks_response (success : bool) = String.concat ""
  (* field 1: null byte*)
  [ "\x00"
  (* field 2: status, 1 byte 0x5a = granted; 0x5b = rejected/failed : *)
  ; (if success then "\x5a" else "\x5b")
  (* Note: the next two fields are "ignored" according to the RFC,
   * but socat (among other clients) refuses to parse the response
   * if it's not zeroed out, so that's what we do (same as ssh): *)
  (* field 3: bigendian port: *)
  ; String.make 2 '\x00'
  (* field 4: "network byte order ip address"*)
  ; String.make 4 '\x00' (* IP *)
  ]

let parse_request buf =
  let buf_len = Bytes.length buf in
  if 9 > buf_len
  then R.error `Incomplete_request
  else
  match buf.[0] , buf.[1], buf.[2], buf.[3] with 
  | exception Invalid_argument _ -> R.error `Incomplete_request 
  | '\x04' , '\x01' , (* socks4a CONNECT TODO *) 
    port_msb, port_lsb (* port *) 
    ->
    let username_offset = 8 in
    begin match Bytes.index_from buf username_offset '\x00' with
    | exception Not_found -> (*no user_id / user_id > 255 *)
        if buf_len < username_offset + 256
        then R.error `Incomplete_request
        else R.error `Invalid_request
    | username_end ->
      let port = (int_of_char port_msb lsl 8) + int_of_char port_lsb in
      let username = Bytes.sub_string buf username_offset (username_end - username_offset) in
      begin match buf.[4], buf.[5], buf.[6] with
      | exception Invalid_argument _ ->
          R.error `Incomplete_request
      | '\x00' , '\x00', '\x00' ->
        let address_offset = 1 + username_end in
        begin match Bytes.index_from buf address_offset '\x00' with
        | exception Not_found -> (*no domain name / domain name > 255 *) 
            if buf_len < address_offset + 256
            then R.error `Incomplete_request
            else R.error `Invalid_request 
        | address_end -> 
          let address = Bytes.sub_string buf address_offset (address_end - address_offset) in
          R.ok @@ `Socks4 { port ; username ; address}
        end
      | _ -> (* address is an IPv4 tuple *)
        let address = String.concat "." List.(map
          (fun i -> string_of_int (int_of_char buf.[i])) [ 4; 5; 6; 7 ] )
        in
        R.ok @@ `Socks4 { port ; username ; address}
      end
    end
  | _ -> R.error `Invalid_request

let parse_response result =
  if 8 > Bytes.length result then
    R.error `Incomplete_response
  else
  if   result.[0] = '\x00' 
    && result.[1] = '\x5a' 
    (* TODO not checking port *) 
    && result.[4] = '\x00' 
    && result.[5] = '\x00' 
    && result.[6] = '\x00' 
    && result.[7] = '\xff' 
  then 
    R.ok ()
  else 
    R.error `Rejected

