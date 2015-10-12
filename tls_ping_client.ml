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

let connect_proxy proxy (ca_public_cert , public_cert , secret_key ) =
  X509_lwt.authenticator (`Ca_file ca_public_cert) >>= fun authenticator ->
  X509_lwt.private_of_pems ~cert:public_cert ~priv_key:secret_key >>= fun cert ->
  (*^-- TODO verify that it's a client cert *)
    let config = Tls.Config.(client ~version:(TLS_1_2,TLS_1_2) ~hashes:[`SHA256] ~authenticator ~certificates:(`Single cert) ~ciphers:Ciphers.supported (*TODO restrict, put config in shared file*) () ) in
  try
    return @@ R.ok @@ Tls_lwt.connect_ext config proxy
  with
  | Tls_lwt.Tls_failure err ->
    return @@ R.error @@ Tls.Engine.string_of_failure err

let handle_irc_client client_in client_out target proxy_details certs =
  let _ = client_out in (* TODO unused variable so far *)
  let _ = client_in in
  connect_proxy proxy_details certs >>= function
  | Error err ->
    Lwt_io.eprintf "err: %s\n" err
  | Ok proxy ->
  let _ = proxy , target in
  Lwt_io.eprintf "connected to proxy\n" >>= fun () ->
  return ()

let handle_client (unix_fd, sockaddr) proxy certs () =
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
  | `Socks4 ({port ; user_id; address } as target) ->
      Lwt_io.eprintf "got request for user '%s' host '%s' port %d!!!\n" user_id address port >>= fun () ->
      handle_irc_client client_in client_out target proxy certs

let listener_service (host,port) proxy certs =
  let open Lwt_unix in
(*  let open_socket = 1 in*)
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
        (Lwt.async (handle_client c proxy certs) ;
        loop s)
    | `Error _ -> failwith "listener failed, should retry"
  in 
  loop s

let run_client listen_host listen_port proxy_host proxy_port ca_public_cert client_public_cert client_secret_key =
  let listen = (listen_host , listen_port) in
  let proxy  = (proxy_host  , proxy_port) in
  let certs   = ca_public_cert , client_public_cert , client_secret_key in
  Lwt_main.run (listener_service listen proxy certs)

(***** cmdliner config *****)
open Cmdliner

(* TODO
let hex_string_64_characters : string Arg.converter =
  (* check that the fingerprint is a 64 character hex string *)
  let parse s =
    (if String.length s <> 64
    then `Error "length must be 64"
    else
    let rec str_filter i =
      match s.[i] with
      | '0'..'9' |'a'..'f'|'A'..'F' when i = 0 -> `Ok s
      | '0'..'9' |'a'..'f'|'A'..'F' -> str_filter (i-1)
      | _ -> `Error ""
    in str_filter 63
    )
  in
  parse, fun ppf (fp) -> Format.fprintf ppf "%s" fp
*)

let listen_host =
  Arg.(value & opt (string) ("127.0.0.1") & info ["listen"]
    ~docv:"LISTEN-ADDRESS" ~doc:"address to bind the client listener to")

let listen_port =
  Arg.(value & opt (int) (6667) & info ["listen-port";"lport"] ~docv:"LISTEN-PORT"
    ~doc:"port to bind the client listener to")

(* TODO
let proxy_fingerprint =
  Arg.(required & pos 0 (some hex_string_64_characters) None
       & info [] ~docv:"PROXY-SHA256"
       ~doc:"sha256 fingerprint of the proxy's TLS certificate")
*)

let proxy_host =
  Arg.(required & pos 0 (some string) None & info []
    ~docv:"PROXY-ADDRESS" ~doc:"address of the proxy")

let proxy_port =
  Arg.(value & opt (int) (1312) & info ["proxy-port";"rport"]
    ~docv:"PROXY-PORT"
    ~doc:"port of the proxy")

let ca_public_cert =
  Arg.(required & pos 1 (some string) None & info []
    ~docv:"CA-PUBLIC-CERT"
    ~doc:"The CA public certificate file shared between proxy and clients")

let client_public_cert =
  Arg.(required & pos 2 (some string) None & info []
     ~docv:"CLIENT-PUBLIC-CERT"
     ~doc:"The client public certificate file used to authenticate to the proxy")

let client_secret_key =
  Arg.(required & pos 3 (some string) None & info []
      ~docv:"CLIENT-SECRET-KEY"
      ~doc:"The client secret key file belonging to this client")

let cmd =
  let doc = "TLS ping client" in
  let man = [
    `S "DESCRIPTION" ;
    `P "$(tname) connects to a TLS ping proxy server" ;
    `S "BUGS" ;
    `P "Please report bugs on the issue tracker at <https://github.com/cfcs/tlspingd/issues>" ;
    `S "SEE ALSO" ;
    `P "<https://github.com/cfcs/tlspingd/blob/master/readme.md>" ]
  in
  Term.(pure run_client $ listen_host $ listen_port $ proxy_host $ proxy_port $ ca_public_cert $ client_public_cert $ client_secret_key ),
  Term.info "tls_ping_client" ~version:"0.1.0" ~doc ~man

let () =
  (* TODO Lwt_daemon.daemonize + Lwt_daemon.logger *)
  match Term.eval cmd with
  | `Error _ -> exit 1
  | _ -> exit 0

