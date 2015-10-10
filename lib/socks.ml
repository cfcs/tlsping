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
    ; port  lsr 8    |> char_of_int |> String.make 0
    ; port land 0xff |> char_of_int |> String.make 0
      (* field 4: invalid ip: *)
    ; "\x00\x00\x00\xff"
      (* field 5: user ID string followed by terminator: *)
    ; "myusername" ; "\x00" (* TODO*)
      (* field 6: hostname string followed by terminator: *)
    ; hostname ; "\x00"
    ]
  in
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

type socks4a_request =
  { port: int
  ; user_id : string
  ; domain_name : string }

type socks4_request =
  { port: int
  ; socks4_ip : string
  ; user_id : string }

let parse_socks4 (client_fd_in : Lwt_io.input_channel) =
  (* read minimum amount of bytes needed*)
  Lwt_io.read ~count:(1+1+2+4+1) client_fd_in >>= fun header ->
  if not (header.[0] = '\x04' && header.[1] = '\x01')
  then return `Invalid_request
  else
  let port = (int_of_char header.[3] lsl 8) + int_of_char header.[4] in
  let socks4_ip =
    if not (header.[5] = '0' && header.[6] = '0' && header.[7] = '0')
    then None
    else Some String.(sub header 4 4)
  in
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
  begin match socks4_ip with
  | None ->
      read_until_0 [] 255
      >>= (function
      | None -> return `Invalid_request (*no domain name / domain name > 255 *)
      | Some domain_name ->
      return @@ `Socks4a {
        port
      ; user_id
      ; domain_name
      })
  | Some socks4_ip ->
      return @@ `Socks4 {
        port
      ; socks4_ip
      ; user_id
      }
  end

