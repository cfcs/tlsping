open Lwt
open Tlsping

type connection =
  { interval  : int
  ; oc        : Lwt_io.output_channel
  ; ic        : Lwt_io.input_channel
  ; address   : string
  ; port      : int
  ; seq_num   : int64
  ; incoming  : string Queue.t
  ; outgoing  : (int64 * string) Queue.t
  }

let connections = Hashtbl.create 10

let handle_incoming ic oc incoming () =
  let rec loop () =
    Lwt_io.read ~count:512 ic >>= fun input ->
    if "" = input then raise End_of_file else
    Lwt_io.printf "handle_incoming: %d bytes read\n" String.(length input) >>= fun () ->
    Queue.add input incoming ;
    Lwt_io.write oc (serialize_incoming input) (* TODO automatically subscribe?*)
    >> loop ()
  in loop ()

let cmd_connect client_oc (`Connect (interval , address , port)) =
  Tlsping.create_socket address >>= function
  | Error () ->
      Lwt_io.eprintf "cmd_connect: create_socket: fail\n"
      (* TODO send Connect_error interval address port *)
      >> return ()
  | Ok (remote_fd , host_inet_addr) ->
  Lwt_io.printf "trying to connect to '%s':%d\n" address port >>
  (try_lwt
    Lwt_unix.connect remote_fd (ADDR_INET (host_inet_addr , port))
  with
  | Unix.Unix_error ( _ , f_n, _) ->
     Lwt_io.eprintf "Unix error '%s' when connecting to target %s:%d\n" f_n address port
  ) >>
  let id = 1 +  Hashtbl.length connections in (*TODO proper counter *)
  let us = { (* TODO tie this to the TLS client cert *)
      interval
    ; oc = Lwt_io.of_fd Output remote_fd
    ; ic = Lwt_io.of_fd Input  remote_fd
    ; address
    ; port
    ; seq_num  = 0L
    ; incoming = Queue.create ()
    ; outgoing = Queue.create ()
    } 
  in
  Hashtbl.add connections id us ;
  (* Start a separate thread to save incoming data: *)
  Lwt_io.write client_oc (serialize_connect_answer Int32.(of_int id) address port)
  >>= fun () ->
  Lwt.async (handle_incoming us.ic client_oc us.incoming) ;
  return ()

let handle_server (ic, (oc : Lwt_io.output_channel)) addr () =
  (** main function for handling a connection from an authenticated client **)
  (* TODO tie all state to the client certificate to allow multiple users *)
  let _ = addr , oc in (* TODO *)
  let hex s = begin match Hex.of_string s with `Hex s -> s end in
  Lwt_io.eprintf "got an authenticated connection from a client!\n" >>
  let rec loop needed_len acc =
  Lwt_io.printf "entering loop, reading %d B\n" needed_len >>
  Lwt_io.read ~count:needed_len ic >>= fun msg ->
  (* handle EOF: *)
  if msg = "" then return () else
  Lwt_io.printf "client->server msg: %d: [%s]\t\t%s\n" String.(length msg)
    (hex acc) (hex msg) >>
  let msg = String.concat "" [acc ; msg] in
  begin match unserialized_of_client_msg msg with
  | `Need_more needed_len ->
    Lwt_io.printf "client->server: read incomplete packet, need bytes: %d\n" needed_len
    >> loop needed_len msg
  | `Subscribe conn_id ->
      let _ = conn_id in
      (* TODO Lwt.async (handle_subscribe conn_id) ; *)
      loop 2 ""
  | `Connect (ping_interval, address, port) as params ->
    Lwt_io.printf "CONNECT request for ping interval %d, host '%s':%d\n"
                  ping_interval address port
    >> cmd_connect oc params
    >> loop 2 ""
  | `Outgoing (conn_id , seq_num , count , msg) ->
      Lwt_io.printf "OUTGOING for conn %ld seq %Ld count %d msg: %s\n"
        conn_id seq_num count (begin match Hex.of_string msg with `Hex s->s end)
        >>= fun () ->
      let conn_id = Int32.to_int conn_id in
      let x = Hashtbl.find connections conn_id in
      (* TODO check if seq_num < x.seq_num and reject *)
      Hashtbl.replace connections conn_id {x with seq_num = Int64.add seq_num Int64.(of_int count)} ;
      Lwt_io.write x.oc msg
      >> loop 2 ""
  | `Invalid _ ->
    Lwt_io.eprintf "got an INVALID packet, TODO kill connection\n"
  end
  in loop 2 ""
  >> Lwt_io.eprintf "shutting down loop\n"

let server_service listen_host listen_port (ca_public_cert : string) proxy_public_cert proxy_secret_key : 'a Lwt.t =
  let open Lwt_unix in
  Tlsping.(tls_config (ca_public_cert , proxy_public_cert , proxy_secret_key)) >>= function {authenticator ; ciphers ; version ; hashes ; certificates} ->
  let config = Tls.Config.(server ~authenticator ~ciphers ~version ~hashes ~certificates ()) in
  Tlsping.create_socket listen_host >>= function
  | Error () ->
      Lwt_io.eprintf "create_socket: fail\n"
      >> return None
  | Ok (s , host_inet_addr) ->
  let () = setsockopt s SO_REUSEADDR true in
  let () = bind s (ADDR_INET (host_inet_addr , listen_port)) in
  let () = listen s 10 in
  let rec loop s =
    match_lwt
      try_lwt
        Tls_lwt.accept_ext config s >|= fun r -> `R r
      with
        | Unix.Unix_error (e, f, p) -> return (`L ("unix: " ^ Unix.(error_message e) ^ f ^ p))
        | Tls_lwt.Tls_alert a -> return (`L (Tls.Packet.alert_type_to_string a))
        | Tls_lwt.Tls_failure f -> return (`L (Tls.Engine.string_of_failure f))
        | _ (*exn*) -> return (`L "loop: exception")
    with
    | `R (channels, addr) ->
      let () = async (handle_server channels addr) in
      loop s
    | `L (msg) ->
      Lwt_io.eprintf "server fucked up: %s\n" msg
      >> loop s
  in loop s
  >> Lwt_io.eprintf "quitting\n"
  >> return (Some ())

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

