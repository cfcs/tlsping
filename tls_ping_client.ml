open Tls
open Rresult
open Lwt

type generate_msg_error =
| TLS_handshake_not_finished
| TLS_not_acceptable_ciphersuite

let generate_msg tls_state payload (seq_num : int64)
  : (Cstruct.t, generate_msg_error) R.t =
  (* encrypt a record containing [payload] and MAC'd with the given [seq_num],
   * using the client keys from [tls_state] *)
  match Engine.epoch tls_state with
  | `InitialEpoch -> Error TLS_handshake_not_finished
  | `Epoch epoch ->
  let open Tls.Core in
  begin match epoch.protocol_version , epoch.ciphersuite with
  | TLS_1_2 ,
    ( `TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    | `TLS_DHE_RSA_WITH_AES_256_CBC_SHA256) ->
    let session = Handshake_common.session_of_epoch epoch in
    let c_context = fst (Handshake_crypto.initialise_crypto_ctx
                      epoch.protocol_version session) in
    let c_context = Tls.State.{ c_context with sequence = seq_num } in
      Engine.encrypt TLS_1_2 (Some c_context) Packet.APPLICATION_DATA payload
      |> snd |> R.ok
  | _ ->
    Error TLS_not_acceptable_ciphersuite
  end

let handle_irc_client client_in client_out =
  let _ = client_out in (* TODO unused variable so far *)
  let _ = client_in in
  return ()

let handle_client (unix_fd, sockaddr) () =
  begin match sockaddr with
  | Lwt_unix.ADDR_INET ( _ (*inet_addr*), port) ->
    Printf.printf "Port: %d\n" port
  | Lwt_unix.ADDR_UNIX _ -> ()
  end ;
  let client_in  = Lwt_io.of_fd Input  unix_fd
  and client_out = Lwt_io.of_fd Output unix_fd in
  match_lwt Socks.parse_socks4 client_in with
  | `Invalid_request ->
      Lwt_io.eprintf "invalid request!\n" (*TODO failwith / logging *)
  | `Socks4 {port ;user_id; address } ->
      Lwt_io.eprintf "got request for user '%s' host '%s' port %d!!!\n" user_id address port >>= fun () ->
      handle_irc_client client_in client_out

let listener_service host port =
  let open Lwt_unix in
  gethostbyname host >>= fun host_entry ->
  let host_inet_addr = Array.get host_entry.h_addr_list 0 in
  let s = socket host_entry.h_addrtype SOCK_STREAM 0 in
  let () = setsockopt s SO_REUSEADDR true in
  let () = bind s (ADDR_INET (host_inet_addr, port )) in
  let () = listen s 10 in
  let rec loop s =
    match_lwt
      try_lwt accept s >>= fun c -> return (`Client c) with
      (*| Unix.Unix_error (e, f, p) -> return (`Error "e")*)
      | _ -> return (`Error "exn")
    with
    | `Client c ->
        (Lwt.async (handle_client c) ;
        loop s)
    | `Error _ -> failwith "listener failed, should retry"
  in
  loop s

let () =
  (* TODO Lwt_daemon.daemonize + Lwt_daemon.logger *)
  let host = "127.0.0.1" and port = 6667 in
  Lwt_main.run (listener_service host port)

