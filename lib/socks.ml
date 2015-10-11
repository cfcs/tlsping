(* A SOCKS4a helper. Wraps a Lwt file_descr
   https://en.wikipedia.org/wiki/SOCKS#SOCKS4a
*)
open Lwt

let connect_client (proxy_fd_in : Lwt_io.input_channel)
                   (proxy_fd_out : Lwt_io.output_channel)
                   hostname port : bool Lwt.t =
  let message = String.concat ""
    [ (* field 1: SOCKS version *)
    "\x04"
      (* field 2: command code: "connect stream": *)
    ; "\x01"
      (* field 3: bigendian port: *)
    ; port land 0xff |> char_of_int |> String.make 0
    ; port  lsr 8    |> char_of_int |> String.make 0
      (* field 4: invalid ip: *)
    ; "\x00\x00\x00\xff"
      (* field 5: user ID string followed by terminator: *)
    ; "root" ; "\x00" (* TODO decide on a sane default or make argument *)
      (* field 6: hostname string followed by terminator: *)
    ; hostname ; "\x00"
    ]
  in
  try_lwt
  Lwt_io.write proxy_fd_out message >>= fun () ->
  Lwt_io.read ~count:(1+1+2+4) proxy_fd_in >>= fun result ->
  if   result.[0] = '\x00'
    && result.[1] = '\x5a'
    (* TODO not checking port *)
    && result.[4] = '\x00'
    && result.[5] = '\x00'
    && result.[6] = '\x00'
    && result.[7] = '\xff'
  then
    return true
  else
    return false
  with
  | End_of_file -> return false

type socks4_request =
  { port    : int
  ; address : string
  ; user_id : string }

let parse_socks4 (client_fd_in : Lwt_io.input_channel) =
  let header = Bytes.make 8 '8' in
  try_lwt
  (* read minimum amount of bytes needed*)
  Lwt_io.read_into_exactly client_fd_in header 0 (1+1+2+4) >>= fun () ->
  if not (header.[0] = '\x04' && header.[1] = '\x01')
  then return `Invalid_request
  else
  let port = (int_of_char header.[2] lsl 8) + int_of_char header.[3] in
  let rec read_until_0 acc max =
    if max = 0 then return None
    else
      Lwt_io.read ~count:1 client_fd_in
    >>= function
      | "\x00" -> return @@ Some String.(concat "" acc)
      | byt    -> read_until_0 (acc @ [byt]) (max - 1)
  in
  read_until_0 [] 255
  >>= function
  | None -> return `Invalid_request (*no user_id / user_id > 255 *)
  | Some user_id ->
  begin match header.[4] = '\x00'
           && header.[5] = '\x00'
           && header.[6] = '\x00' with
  | true  ->
      read_until_0 [] 255
      >>= (function
      | None -> return `Invalid_request (*no domain name / domain name > 255 *)
      | Some address -> return @@ `Addr address)
  | false ->
    return @@ `Addr (String.concat "." List.(map
      (fun i -> string_of_int (int_of_char header.[i])) [ 4; 5; 6; 7 ] ))
  end >>= (function
  | `Addr address ->
    return @@ `Socks4 {
      port
    ; address
    ; user_id
  }
  | `Invalid_request as ir -> return ir )
  with
  | End_of_file -> return `Invalid_request

