(* A SOCKS4a helper. Wraps a Lwt file_descr

   tlsping uses the "user_id" field in socks4 to hold the hex-encoded
   sha256 fingerprint of the x509 certificate of address:port
*)

open Lwt
open Socks4

let connect_client (proxy_fd_in   : Lwt_io.input_channel)
                   (proxy_fd_out  : Lwt_io.output_channel)
                    hostname port : bool Lwt.t =
  let message = Socks4.socks_request ~username:"root" hostname port in
  try_lwt
  Lwt_io.write proxy_fd_out message >>= fun () ->
  Lwt_io.read ~count:(1+1+2+4) proxy_fd_in >>= fun result ->
  (*TODO handle case when fewer than 8 bytes are read *)
  begin match Socks4.parse_response result with
  | Ok () ->
      return true
  | Error _ ->
      return false
  end
  with
  | End_of_file -> return false

let receive_request (client_fd_in : Lwt_io.input_channel) =
  (* read minimum amount of bytes needed*)
  let rec read_request header =
    begin match Socks4.parse_request header with
    | Error `Incomplete_request ->
      Lwt_io.read ~count:1 client_fd_in
      >>= (function
      | "" -> return `Invalid_request
      | s  -> read_request @@ String.concat "" [header ; s])
    | Error `Invalid_request -> return `Invalid_request
    | Ok (`Socks4 request) ->
        if 64 <> String.length request.username (*tlsping uses 64byte hex fingerprint for pinning*)
        then return @@ `Invalid_fingerprint request.username
        else return @@ `Socks4 request
    end
  in read_request ""

