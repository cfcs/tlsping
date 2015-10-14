open Tlsping
open Tls
open Rresult
open Lwt
(*TODO
let states = Hashtbl.create 10
*)
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

type tls_state_ref_t = {mutable tls_state : Tls.Engine.state option }
let tls_state_ref : tls_state_ref_t = { tls_state = None }

let connect_proxy client_out (host , port) certs =
  Tlsping.(tls_config certs) >>= function { authenticator ; ciphers ; version ; hashes ; certificates } ->
  let config =Tls.Config.client ~authenticator ~ciphers ~version ~hashes ~certificates () in
  Lwt_io.printf "connecting to proxy\n" >>
  try_lwt
    create_socket host >>= function
    | Error () -> return @@ R.error "unable to resolve proxy hostname"
    | Ok (fd, proxy) ->
    (* the ServerName on the cert might not match the actual hostname we use,
     * so we need to provide it in ~host: below *)
        Lwt_unix.connect fd (ADDR_INET (proxy, port)) >>
        Tls_lwt.Unix.client_of_fd config ~host:"proxy.example.org" fd (* TODO "proxy.example.org" should obviously be a parameter, testing only! *)
        >>= fun tls_t ->
        Lwt_io.write client_out @@ Socks.socks_response true >>
        return @@ R.ok Tls_lwt.(of_t tls_t)
  with
  | Unix.Unix_error (Unix.ECONNREFUSED, f_n , _) ->
      Lwt_io.write client_out @@ Socks.socks_response false >>
      return @@ R.error @@ "Unix error: connection refused: " ^ f_n
  | Tls_lwt.Tls_failure err ->
      return @@ R.error @@ "Tls_failure: " ^
      begin match err with
      | `Error (`AuthenticationFailure (`InvalidServerName _ as valerr)) ->
        "ServerName mismatch: " ^ X509.Validation.validation_error_to_string valerr
      | _ -> Tls.Engine.string_of_failure err
      end

let handle_outgoing client_in proxy_out () =
  let rec loop () =
    (* TODO handle disconnect / broken line: *)
    Lwt_io.read_line client_in >>= fun line ->
    (* when using Lwt_io.read instead:
       if "" = line then raise End_of_file ; *)
    let tls_state = begin match tls_state_ref.tls_state with Some t -> t | None -> failwith "fail" end in
    begin match Tls.Engine.can_handle_appdata tls_state with
    | true ->
      let line = line ^ "\n" in
      begin match Tls.Engine.send_application_data tls_state [Cstruct.(of_string line)] with
      | None ->
          (* TODO: POOF - session dead*)
          Lwt_io.eprintf "TODO error handling; TLS fucked up\n"
      | Some (tls_state , cstruct_out) ->
          (* TODO sync to global state: *)
          tls_state_ref.tls_state <- Some tls_state ;
          Lwt_io.write proxy_out (serialize_outgoing 1l 0L Cstruct.(to_string cstruct_out))
      end
    | false ->
      (* TODO queue outgoing, don't drop*)
      Lwt_io.eprintf "TODO! dropping line because no conn: '%s'\n" line
    end
    >> loop ()
  in
  try_lwt loop () with
  | End_of_file -> return ()

let handle_irc_client client_in client_out target proxy_details certs =
  connect_proxy client_out proxy_details certs >>= function
  | Error err ->
    Lwt_io.eprintf "err: %s\n" err
  | Ok (proxy_in, proxy_out) ->
  Lwt_io.eprintf "connected to proxy\n" >>
  begin match serialize_connect 60 (target.Socks.address, target.port) with
  | None -> Lwt_io.eprintf "error: unable to serialize connect"
  | Some connect_msg ->
  (* Ask the proxy to connect to target.address: *)
  Lwt_io.write proxy_out connect_msg >>= fun () ->

  let rec loop count acc =
    Lwt_io.printf "loop reading connect status need %d bytes\n" count >>
    Lwt_io.read ~count proxy_in >>= fun msg ->
    if "" = msg then failwith "invalid bytes todo\n" else
    let msg = String.concat "" [acc ; msg] in
    begin match unserialized_of_server_msg msg with
    | `Need_more count -> loop count msg
    | _ as m -> return m
    end
  in loop 2 "" >>= function
  | `Invalid _ | `Status_answer _ | `Incoming _ |`Need_more _ ->
      Lwt_io.eprintf "error from proxy: unexpected message received\n"
  | `Connect_answer (conn_id , _ , _) when conn_id = 0l -> (* if failed *)
      Lwt_io.eprintf "error from proxy: no connect to %s\n" target.address
      (*TODO kill connection*)
  | `Connect_answer (conn_id , _ , _) ->
  Lwt_io.eprintf "yo I have a conn_id %ld\n" conn_id >>= fun () ->
  (* Initialize TLS connection from client -> target *)
  X509_lwt.authenticator (`Hex_fingerprints (`SHA256 ,
                            [target.address , target.fingerprint] ))
  >>= fun authenticator ->
  return @@ Tls.Config.client
     ~authenticator
     ~ciphers:[ `TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
              ; `TLS_DHE_RSA_WITH_AES_256_CBC_SHA ] (*TODO allow AES_128 ?*)
     ~version:Tls.Core.(TLS_1_2 , TLS_1_2) (* g *)
     ~hashes:[`SHA256 ; `SHA1] ()
  >>= fun tls_config ->
  return @@ Tls.Engine.client tls_config
  >>= fun (tls_state, client_hello) ->
  (* Initiate a TLS connection: *)
  tls_state_ref.tls_state <- Some tls_state ;
  Lwt_io.write proxy_out (serialize_outgoing conn_id 0L Cstruct.(to_string client_hello))
  >>= fun () ->

  (* setup thread that encrypts outgoing messages by proxy *)
  Lwt.async (handle_outgoing client_in proxy_out) ;

  (* successfully connected; handle answers *)
  let rec loop needed_len acc =
    Lwt_io.printf "entering loop - %d\n" needed_len >>= fun () ->
    Lwt_io.read ~count:needed_len proxy_in >>= fun msg ->
    if msg = "" then return () else
    let msg = String.concat "" [acc ; msg] in
    begin match unserialized_of_server_msg msg with
    | `Need_more needed_len ->
      Lwt_io.printf "Reading from server: Need more bytes: %d\n" needed_len
      >> loop needed_len msg

    | `Connect_answer _ ->
      Lwt_io.printf "CONNECT_ANSWER\n"
      (* TODO don't automatically assume CONNECT was successful *)
      >> loop 2 ""

    | `Incoming msg ->
      (* TODO decrypt ; handle write errors; buffer if client disconnected? *)
      let tls_state = begin match tls_state_ref.tls_state with Some t -> t | None -> failwith "fail" end in
      begin match Tls.Engine.handle_tls tls_state Cstruct.(of_string msg) with
      | `Ok (`Ok tls_state , `Response resp, `Data msg) ->
         tls_state_ref.tls_state <- Some tls_state ;
         begin match resp with
         | Some resp_data ->
             Lwt_io.write proxy_out (serialize_outgoing conn_id 0L Cstruct.(to_string resp_data))
         | None -> return ()
         end
         >>
         begin match msg with
         | Some msg_data -> Lwt_io.write client_out Cstruct.(to_string msg_data)
         | None -> return ()
         end
         >> loop 2 ""
      | `Ok (_ , `Response resp , `Data msg) ->
          let _ = resp , msg in
          Lwt_io.eprintf "TLS EOF or ALERT\n"
      | `Fail (failure , `Response resp) ->
          let _ = failure, resp in
          Lwt_io.eprintf "TLS FAIL: %s\n" @@ Tls.Engine.string_of_failure failure
      end

    | `Status_answer _ ->
      Lwt_io.printf "STATUS_ANSWER\n"
      >> loop 2 ""

    | `Invalid _ ->
      Lwt_io.eprintf "Got invalid packet from server; shutting down\n"
    end
  in loop 2 ""
  end

let handle_client (unix_fd, sockaddr) proxy certs () =
  begin match sockaddr with
  | Lwt_unix.ADDR_INET ( _ (*inet_addr*), port) ->
    Lwt_io.printf "Incoming connection, src port: %d\n" port
  | Lwt_unix.ADDR_UNIX _ -> return ()
  end >>
  let client_in  = Lwt_io.of_fd Input  unix_fd
  and client_out = Lwt_io.of_fd Output unix_fd in
  match_lwt Socks.parse_socks4 client_in with
  | `Invalid_fingerprint fp ->
      Lwt_io.eprintf "socks4 handler: invalid sha256 fingerprint: %s\n" fp (* TODO logging*)
  | `Invalid_request ->
      Lwt_io.eprintf "invalid request!\n" (*TODO failwith / logging *)
  | `Socks4 ({port ; fingerprint; address } as target) ->
      Lwt_io.eprintf "got request for host '%s' port %d fp %s\n" address port fingerprint >>
      handle_irc_client client_in client_out target proxy certs

let listener_service (host,port) proxy certs =
  let open Lwt_unix in
  create_socket host >>= function
  | Error () -> failwith "unable to resolve listen addr"
  | Ok (s , host_inet_addr) ->
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
  (* TODO could also have type "https"/"irc"/"xmpp"/whatever *)
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

