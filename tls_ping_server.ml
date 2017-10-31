open Lwt
open Tlsping

type connection =
  { interval  : int
  ; oc        : Lwt_io.output_channel
  ; ic        : Lwt_io.input_channel
  ; last_output_time : float
  ; address   : string
  ; port      : int
  ; owner_fp  : string
  ; seq_num   : int64
  ; incoming  : string Queue.t (*TODO should be an Array*)
  ; incoming_condition : int Lwt_condition.t (* TODO use mutex? http://ocsigen.org/lwt/2.5.0/api/Lwt_condition*)
  ; outgoing  : (int64 * string) Queue.t
  }

let connections = Hashtbl.create 10

let connection_status_of_connection conn_id conn : Tlsping.connection_status =
  { conn_id
  ; ping_interval = conn.interval
  ; address       = conn.address
  ; port          = conn.port
  ; seq_num       = conn.seq_num
  ; queue_length  = Queue.length conn.outgoing |> Int32.of_int
  }

let owner_fp_of_state tls_state =
  X509.key_fingerprint ~hash:`SHA256 @@ X509.public_key (match Tls.Core.((
    begin match Tls.Engine.epoch tls_state with
    | `Epoch x -> x
    | `InitialEpoch -> failwith "TODO initialepoch"
    end).peer_certificate) with Some x -> x | None -> failwith "no cert")
  |> Cstruct.to_string

let handle_incoming conn_id ic incoming incoming_condition outgoing () =
  let rec loop () =
    Lwt_io.read ~count:65537 ic >>= fun input ->
    if "" = input then raise End_of_file else
    let next_queued , max_queued =
      Queue.fold (fun (next , max) -> fun (seq,_) ->
        (int64_min seq next , int64_max seq max)
      )
      (Int64.max_int , 0L) outgoing 
    in
    Lwt_io.printf "handle_incoming: %d bytes read nextq: %Ld queued: %Ld\n" String.(length input)  next_queued max_queued >>= fun () ->
    Queue.add (serialize_incoming conn_id next_queued max_queued input) incoming ;
    Lwt_condition.broadcast incoming_condition 1 ;
    loop ()
  in
  try_lwt loop () with
  | End_of_file -> Lwt_io.eprintf "handle_incoming: End_of_file TODO\n"
  | Unix.Unix_error(Unix.ECONNRESET, "read", "") -> Lwt_io.eprintf "handle_incoming: broken read TODO\n"

let handle_subscribe condition_input_available queue oc () =
  (*TODO this scales rather badly when the queue is large,
   *     and is essentially a dirty hack. TODO rewrite *)
  (* TODO: should verify owner_fp *)
  let rec loop () =
    Lwt_condition.wait condition_input_available >>= fun amount ->
    let skip = ref @@ (Queue.(length queue) - amount) in
    let msgs = List.rev @@ Queue.fold (
      fun acc -> fun msg ->
        begin match !skip with
        | 0 -> msg :: acc
        | _ -> skip := !skip -1 ; acc
        end
      ) [] queue
    in
    Lwt_io.eprintf "handle_subscribe %d msgs popped: %d\n" amount List.(length msgs) >>= fun () ->
      Lwt_list.iter_s (fun msg -> Lwt_io.write oc msg) msgs
    >>=fun()-> loop ()
  in loop ()

let handle_interval conn_id () =
  let rec send_pong () =
    begin match Hashtbl.find connections conn_id with
    | exception Not_found -> (*TODO die*)
        Lwt_io.eprintf "handle_interval: shutting down loop\n"
    | x ->
    let now = Unix.time () in
    begin match x.last_output_time +. (float_of_int x.interval) > now with
    | true ->
      return ()
    | false ->
      let rec get_pong () =
        begin match Queue.pop x.outgoing with
        | (s , msg) when s = x.seq_num -> s , msg
        | (_ , _) (*when discard < x.seq_num*) -> get_pong ()
        | exception Queue.Empty -> x.seq_num , "" (* give up TODO kill connection *)
        end
      in
      begin match get_pong () with
      | _ , "" | 0L , _ ->
          Lwt_io.eprintf "UNABLE TO SEND PING FOR %s:%d, TODO kill connection\n" x.address x.port
      | seq_num , msg ->
          Lwt_io.eprintf "SENDING PING %Ld -> %Ld (remaining: %d)\n" x.seq_num seq_num Queue.(length x.outgoing) >>= fun () ->
          Hashtbl.replace connections conn_id
            {x with
              seq_num = Int64.succ x.seq_num
            ; last_output_time = now } ;
          Lwt_io.write x.oc msg
      end
    end
    >> Lwt_unix.sleep 1.0 >> send_pong ()
    end
  in
  send_pong ()

let cmd_connect tls_state client_oc (`Connect (interval , address , port)) =
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
        (* TODO interval http://ocsigen.org/lwt/2.5.0/api/Lwt_timeout *)
    ; oc = Lwt_io.of_fd Output remote_fd
    ; ic = Lwt_io.of_fd Input  remote_fd
    ; last_output_time = Unix.time ()
    ; address
    ; port
    ; owner_fp = owner_fp_of_state tls_state
    ; seq_num  = 0L
    ; incoming = Queue.create ()
    ; incoming_condition = Lwt_condition.create ()
    ; outgoing = Queue.create ()
    } 
  in
  Hashtbl.add connections id us ;
  (* Start a separate thread to save incoming data: *)
  Lwt_io.write client_oc (serialize_connect_answer Int32.(of_int id) address port)
  >>= fun () ->
  Lwt.async (handle_subscribe us.incoming_condition us.incoming client_oc ) ;
  Lwt.async (handle_incoming Int32.(of_int id) us.ic us.incoming us.incoming_condition us.outgoing) ;
  Lwt.async (handle_interval id) ;
  return ()

let handle_server (tls_state , (ic, (oc : Lwt_io.output_channel))) () =
  (** main function for handling a connection from an authenticated client **)
  (* TODO tie all state to the client certificate to allow multiple users *)
  let hex s = begin match Hex.of_string s with `Hex s -> s end in
  Lwt_io.eprintf "got an authenticated connection from a client!\n" >>

  let rec loop needed_len acc =
  Lwt_io.printf "entering loop, reading %d B\n" needed_len >>
  Lwt_io.read ~count:needed_len ic >>= fun msg ->
  (* handle EOF: *)
  if msg = "" then Lwt_io.eprintf "handle_server loop: broken read\n" >>= fun() -> return () else
  Lwt_io.printf "client->server msg: %d: [%s]\t\t%s\n" String.(length msg)
    (hex acc) (hex msg) >>
  let msg = String.concat "" [acc ; msg] in
  begin match unserialized_of_client_msg msg with
  | `Need_more needed_len ->
      Lwt_io.printf "client->server: read incomplete packet, need bytes: %d\n" needed_len
      >> loop needed_len msg
  | `Subscribe conn_id ->
      let x = Hashtbl.find connections Int32.(to_int conn_id) in
      if owner_fp_of_state tls_state = x.owner_fp then
      (Lwt.async (handle_subscribe x.incoming_condition x.incoming oc) ;
      loop 2 "")
      else Lwt_io.eprintf "SUBSCRIBE: CAN'T SUBSCRIBE TO OTHER PERSON'S CONNECTION\n"
  | `Connect (ping_interval, address, port) as params ->
      Lwt_io.printf "CONNECT request for ping interval %d, host '%s':%d\n"
                    ping_interval address port
      >> cmd_connect tls_state oc params
      >> loop 2 ""
  | `Status (first_conn_id , last_conn_id) ->
      Lwt_io.printf "STATUS %ld - %ld, sending response\n" first_conn_id last_conn_id >>= fun() ->
      let conn_statuses = Hashtbl.fold
        (fun conn_id -> fun conn -> fun acc ->
            connection_status_of_connection Int32.(of_int conn_id) conn :: acc )
        connections
        [] |> List.rev
      in
      Lwt_io.write oc (serialize_status_answer conn_statuses)
      >> loop 2 ""
  | `Outgoing (conn_id , pkt_seq_num , count , msg) ->
      Lwt_io.printf "OUTGOING for conn %ld seq %Ld count %d msg: %s\n"
        conn_id pkt_seq_num count (begin match Hex.of_string msg with `Hex s->s end)
        >>= fun () ->
      let conn_id = Int32.to_int conn_id in
      let x = Hashtbl.find connections conn_id in
      begin match pkt_seq_num , Int64.(sub pkt_seq_num x.seq_num) with
      | 1L , -1L (* TODO work-around to handle initial handshake *)
      | _ , 0L ->
          Hashtbl.replace connections conn_id
          {x with
            (* Update next expected sequence number: *)
            seq_num = Int64.add pkt_seq_num Int64.(of_int count)
            (* Update PING interval timeout:  *)
          ; last_output_time = Unix.time ()
          } ;
          Lwt_io.write x.oc msg
          (* TODO xxx
          >>=fun()->
          (serialize_outgoing_ack Int32.(of_int conn_id (*TODO*)) `Ok pkt_seq_num x.seq_num
          |> Lwt_io.write oc)
          *)
          >>=fun()-> loop 2 ""
      | _ , d when d < 0L ->
          (* ask client to resend*)
          Lwt_io.eprintf "Asking client to resend %Ld as %Ld\n" pkt_seq_num x.seq_num
          (* TODO xxx
          >>= fun()->
          serialize_outgoing_ack Int32.(of_int conn_id (*TODO*)) `Resend pkt_seq_num x.seq_num
          |> Lwt_io.write oc *)
          >>=fun()-> loop 2 ""
      | _ , _ ->
          Lwt_io.eprintf "OUTGOING - out of order transmitted seq_num: %Ld; previous: %Ld) -> %Ld\n" pkt_seq_num x.seq_num Int64.(sub pkt_seq_num x.seq_num)
      end
  | `Queue (conn_id , seq_num, msgs) ->
      Lwt_io.eprintf "QUEUE: conn_id: %ld seq_num: %Ld msg count: %d\n"
        conn_id seq_num List.(length msgs)
      >>
      let conn_id = Int32.to_int conn_id in
      let x = Hashtbl.find connections conn_id in
      let rec add_q n = function
      | msg :: tl ->
          Queue.add (n, msg) x.outgoing ;
          add_q Int64.(add n 1L) tl
      | [] -> loop 2 ""
      in add_q seq_num msgs
  | `Invalid _ ->
      Lwt_io.eprintf "got an INVALID packet, TODO kill connection\n"
  end
  in loop 2 ""
  >>=fun() ->
    (* TODO Hashtbl.remove connections conn_id ; *)
    Lwt_io.eprintf "shutting down loop\n" (* TODO kill connections and clean up queues as relevant*)

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
  bind s (ADDR_INET (host_inet_addr , listen_port)) >>= fun () ->
  let () = listen s 10 in
  let rec loop s =
    match_lwt
      try_lwt
        (* Tls_lwt.Unix provides no way to liberate the fd from the `t`, so we need to copy-paste some code: *)
        (* match Tls.State.state.encryptor with Some crypto_context -> crypto_context.sequence*)
        (*Lwt_unix.accept s >>= fun (fd, addr) ->*)
        Tls_lwt.Unix.accept config s >|= fun (unix_t, _) ->
        begin match unix_t.state with
        | `Active t -> `R (t, Tls_lwt.of_t unix_t)
        | `Eof | `Error _ -> `L "Tls_lwt.Unix.accept error / eof"
        end
      with
        | Unix.Unix_error (e, f, p) -> return (`L ("unix: " ^ Unix.(error_message e) ^ f ^ p))
        | Tls_lwt.Tls_alert a -> return (`L (Tls.Packet.alert_type_to_string a))
        | Tls_lwt.Tls_failure f -> return (`L (Tls.Engine.string_of_failure f))
        | _ (*exn*) -> return (`L "loop: exception")
    with
    | `R (channels) ->
      let () = async (handle_server channels) in
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

