open Lwt

let handle_server (ic, oc) addr () =
  let _ = addr in (* TODO *)
  Lwt_io.eprintf "got an authenticated connection from a client!\n" >>= fun () ->
  Lwt_io.read_line ic >>= fun line ->
  Lwt_io.write_line oc line

let server_service listen_host listen_port (ca_public_cert : string) proxy_public_cert proxy_secret_key =
  Tlsping.(tls_config (ca_public_cert , proxy_public_cert , proxy_secret_key)) >>= function {authenticator ; ciphers ; version ; hashes ; certificates} ->
  let config = Tls.Config.(server ~authenticator ~ciphers ~version ~hashes ~certificates ()) in
(*TODO why doesn't this throw an error if you omit the authenticator? *)
  let open Lwt_unix in
  gethostbyname listen_host >>= fun host_entry ->
  let host_inet_addr = Array.get host_entry.h_addr_list 0 in
  let s = socket host_entry.h_addrtype SOCK_STREAM 0 in
  let () = setsockopt s SO_REUSEADDR true in
  let () = bind s (ADDR_INET (host_inet_addr , listen_port)) in
  let () = listen s 10 in
  let rec loop s =
    match_lwt
      try_lwt
        Tls_lwt.accept_ext config s >|= fun r -> `R r
      with
        | Unix.Unix_error (e, f, p) -> return (`L (Unix.(error_message e) ^ f ^ p))
        | Tls_lwt.Tls_alert a -> return (`L (Tls.Packet.alert_type_to_string a))
        | Tls_lwt.Tls_failure f -> return (`L (Tls.Engine.string_of_failure f))
        | _ (*exn*) -> return (`L "loop: exception")
    with
    | `R (channels, addr) ->
      let () = async (handle_server channels addr) in
      loop s
    | `L (msg) ->
      Lwt_io.eprintf "server fucked up: %s\n" msg >> loop s
  in
  loop s >>= fun () ->
  Lwt_io.eprintf "well that fucked up, end of infinite loop\n"

let run_server a b c d e =
  Lwt_main.run (server_service a b c d e)

(***** cmdliner *****)
open Cmdliner

let listen_host =
  Arg.(value & opt (string) ("127.0.0.1") & info ["listen"]
    ~docv:"LISTEN-ADDRESS" ~doc:"address to bind the client listener to")

let listen_port =
  Arg.(value & opt (int) (1312) & info ["listen-port";"lport"] ~docv:"LISTEN-PORT"
    ~doc:"port to bind the proxy listener to")

let ca_public_cert =
  Arg.(required & pos 0 (some string) None & info []
    ~docv:"CA-PUBLIC-CERT"
    ~doc:"The CA public certificate file shared between proxy and clients")

let proxy_public_cert =
  Arg.(required & pos 1 (some string) None & info []
    ~docv:"PROXY-PUBLIC-CERT"
    ~doc:"The proxy public certificate file used to authenticate to clients")

let proxy_secret_key =
  Arg.(required & pos 2 (some string) None & info []
    ~docv:"PROXY-SECRET-KEY"
    ~doc:"The proxy secret key file belonging to this proxy instance")

let cmd =
  let doc = "TLS ping client" in
  let man = [
    `S "DESCRIPTION" ;
    `P "$(tname) listens for connections from tls-ping-client" ;
    `S "BUGS" ;
    `P "Please report bugs on the issue tracker at <https://github.com/cfcs/tlspingd/issues>" ;
    `S "SEE ALSO" ;
    `P "<https://github.com/cfcs/tlspingd/blob/master/readme.md>" ]
  in
  Term.(pure run_server $ listen_host $ listen_port $ ca_public_cert $ proxy_public_cert $ proxy_secret_key),
  Term.info "tls_ping_server" ~version:"0.1.0" ~doc ~man

let () =
  (* TODO Lwt_daemon.daemonize + Lwt_daemon.logger *)
  match Term.eval cmd with
  | `Error _ -> exit 1
  | _ -> exit 0

