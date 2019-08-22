open Tlsping
open Rresult
open Lwt
open Lwt.Infix

type encrypt_msg_error =
| TLS_handshake_not_finished
| TLS_state_error

let encrypt_queue tls_state payloads seq_num_offset =
  let rec encrypt_msg tls_state payloads acc =
    (* encrypt a record containing [payload] and MAC'd with the given [seq_num],
     * using the client keys from [tls_state] *)
    begin match payloads , tls_state.Tls.State.encryptor with
      | (payload :: payloads) , Some encryptor ->
        begin match Tls.Engine.send_application_data
                      tls_state [Cstruct.(of_string payload)] with
        | None -> R.error TLS_state_error
        | Some (tls_state , encrypted) ->
          encrypt_msg tls_state payloads
            ((encryptor.sequence , encrypted) :: acc)
        end
      | [] , Some _ -> R.ok (tls_state , List.rev acc)
      | _  , None   -> R.error TLS_state_error
    end
  in
  match tls_state.Tls.State.encryptor with
  | Some { sequence ; _ } when (sequence > seq_num_offset) ->
    (* the `when` guard makes sure we only encrypt data "ahead" of time *)
    R.error TLS_state_error (* TODO error type for this *)
  | Some { cipher_st ; _ } ->
    let new_state : Tls.State.state =
      {tls_state with encryptor =
                        (Some {Tls.State.cipher_st ;
                               sequence = seq_num_offset }
                         :Tls.State.crypto_state)} in
    encrypt_msg new_state payloads []
  | None ->
    R.error TLS_state_error

type connection_state =
  { mutable tls_state : Tls.Engine.state
  ; mutable outgoing  : (int64 * string) list
  ; address           : string
  ; port              : int
  ; mutable max_covered_sequence : int64
  }
let states = Hashtbl.create 5

let connect_proxy client_out (host , port) certs =
  Tlsping.(tls_config certs) >>=
  function { authenticator ; ciphers ; version ; hashes ; certificates } ->
    let config = Tls.Config.client ~authenticator ~ciphers ~version ~hashes ~certificates () in
    Logs.debug (fun m -> m "connecting to proxy") ;
    Lwt.catch (fun () ->
        create_socket host >>= function
        | Error () -> return @@ R.error "unable to resolve proxy hostname"
        | Ok (fd, proxy) ->
          (* the ServerName on the cert might not match the actual hostname we use,
           * so we need to provide it in ~host: below *)
          Lwt_unix.connect fd (ADDR_INET (proxy, port)) >>=fun()->
          Tls_lwt.Unix.client_of_fd config ~host:"proxy.example.org" fd (* TODO "proxy.example.org" should obviously be a parameter, testing only! *)
          >>= fun tls_t ->
          Lwt_io.write client_out @@
          (Socks.make_socks5_response
            Succeeded ~bnd_port:0
            (Domain_address host) |> R.get_ok) >>=fun()->
          (return @@ R.ok Tls_lwt.(of_t tls_t)))
      (function
        | Unix.Unix_error (Unix.ECONNREFUSED, f_n , _) ->
          Lwt_io.write client_out @@ (Socks.make_socks5_response
            Host_unreachable ~bnd_port:0
            (Domain_address host) |> R.get_ok) >>=fun()->
          return @@ R.error @@ "Unix error: connection refused: " ^ f_n
        | Tls_lwt.Tls_failure err ->
          return @@ R.error @@
          "Tls_failure: " ^
          begin match err with
            | `Error (`AuthenticationFailure (valerr)) ->
              Fmt.strf "ServerName mismatch: %a"
              X509.Validation.pp_validation_error valerr
            | _ -> "XXYYZ" ^ Tls.Engine.string_of_failure err
          end
        | _ -> failwith "TODO catch this exception"
      )

let send_pings_if_needed conn_id proxy_out =
  let get_seq s = begin match s.Tls.State.encryptor with Some {sequence; _} -> sequence | None -> -1337L end in
  let conn_state = Hashtbl.find states conn_id in (*TODO handle not found*)
  let offset     = int64_max conn_state.max_covered_sequence (get_seq conn_state.tls_state) in
  let next_seq   = Int64.succ @@ get_seq conn_state.tls_state in
  let new_offset =
    let rec lol proposed =
      begin match 1 = Int64.compare offset proposed with
        | false -> begin match 1 = Int64.compare next_seq Int64.(sub proposed 5L) with
            | false -> proposed
            | true -> lol Int64.(add proposed 10L)
          end
        | true  -> lol Int64.(add proposed 10L)
      end in lol 10L
  in
  let pings =
    let rec gen_pings acc = function
      | 0L -> acc
      | i ->
        gen_pings
          (Printf.(sprintf "PING :TLSPiNG:%Ld\r\n" Int64.(add i offset))::acc)
          Int64.(pred i)
    in
    conn_state.max_covered_sequence <- new_offset ;
    Hashtbl.replace states conn_id conn_state ;
    gen_pings [] Int64.(sub new_offset offset)
  in
  if pings = [] then begin
    Logs.debug (fun m ->
        m "not sending pings since we are at offset %Ld and have %Ld queued"
          next_seq conn_state.max_covered_sequence) ;
    Lwt.return_unit
  end else begin
    Logs.debug (fun m ->
        m "sending %d pings: amount %Ld max: %Ld offset: %Ld"
          List.(length pings) new_offset conn_state.max_covered_sequence offset
      ) ;
    begin match encrypt_queue conn_state.tls_state pings offset with
      | Ok (_ , pings) ->
        Lwt_list.map_s (fun (seq, cout) ->
            Logs.debug (fun m -> m "queuing %Ld" seq) ;
            (return @@ Cstruct.to_string cout)
          ) pings >>= fun pings ->
        Lwt_list.iter_s (fun m -> Lwt_io.write proxy_out m)
        @@ serialize_queue ~conn_id offset pings
      | Error _ ->
        Logs.err (fun m -> m "outgoing: TODO error generating PINGs") ;
        Lwt.return_unit
    end
  end

let handle_outgoing conn_id client_in proxy_out () =
  let rec loop () =
    (* TODO handle disconnect / broken line: *)
    Lwt_io.read_line client_in >>= fun line ->
    (* when using Lwt_io.read instead:
       if "" = line then raise End_of_file ; *)
    let line = line ^ "\r\n" in
    let conn_state = Hashtbl.find states conn_id in (*TODO handle not found*)
    begin match conn_state.tls_state.encryptor with
      | None ->
        Logs.err (fun m -> m "TODO error no encryptor state") ;
        Lwt.return_unit
      (*TODO should queue this and send it as soon as the TLS session is established *)
      | Some {sequence = target_sequence; _ } ->
        begin match encrypt_queue conn_state.tls_state [line] target_sequence with
          | Ok ( tls_state , msg_list ) ->
            conn_state.tls_state <- tls_state ;
            let serialized_msgs = List.map (fun (msg_sequence , cout) ->
                conn_state.outgoing <- (msg_sequence , line) :: conn_state.outgoing ;
                serialize_outgoing conn_id msg_sequence Cstruct.(to_string cout)
              ) msg_list |> String.concat ""
            in
            (*TODO: if this fails, wait for reconnect: *)
            Lwt_io.write proxy_out serialized_msgs >>= fun() ->
            send_pings_if_needed conn_id proxy_out
          | Error _ ->
            Logs.err (fun m -> m "Unable to encrypt and send outgoing message");
            Lwt.return_unit
        end
    end
    >>= fun () -> loop ()
  in
  Lwt.catch loop
    (function End_of_file -> return ()
            | _ -> return () (*TODO*) )

let handle_incoming ~proxy_out ~client_out ~conn_id ~next_seq ~queued_seq ~msg =
  (* TODO decrypt ; handle write errors; buffer if client disconnected? *)
  let conn_state = Hashtbl.find states conn_id in (*TODO handle not found?*)
  begin match Tls.Engine.handle_tls conn_state.tls_state
                Cstruct.(of_string msg) with
  | `Ok (`Ok tls_state , `Response resp, `Data msg) ->
    begin match tls_state.encryptor with
      | Some {cipher_st ; sequence } ->
        conn_state.tls_state
        <- {tls_state with
            encryptor = Some
                ({cipher_st ;
                  sequence = Tlsping.int64_max sequence
                      (if next_seq <> Int64.max_int
                       then next_seq else 0L)
                 }:Tls.State.crypto_context)}
      | None ->
        conn_state.tls_state <- tls_state
    end ;
    conn_state.max_covered_sequence <- int64_max queued_seq
        conn_state.max_covered_sequence ;
    begin match resp with
      | Some resp_data ->
        let sequence = begin match tls_state.encryptor with
          | Some crypto_context -> crypto_context.sequence
          | None-> failwith "TODO" end in
        Logs.warn (fun m -> m "need to respond") ;
        Lwt_io.write proxy_out (serialize_outgoing conn_id sequence
                                  Cstruct.(to_string resp_data))
      | None -> return ()
    end
    >>= fun() ->
    begin match msg with
      | Some msg_data ->
        (* TODO
           String.index_from ":server.example.org PONG server.example.org :TLSPiNG:10" 0 ' '
           let first_space = 1 + String.index_from msg_data 0 ' ' in
           let second_space = String.index_from msg_data first_space ' ' in
           let server = String.sub msg_data 1 (first_space -2) in
           match String.sub msg_data first_space (second_space - first_space) with
           | "PONG :TLSPiNG:"
        *)
        Logs.debug (fun m ->
            m "Incoming: remote next_seq: %Ld queued_seq: %Ld"
              next_seq queued_seq) ;
        Lwt_io.write client_out Cstruct.(to_string msg_data)
        >>=fun()-> send_pings_if_needed conn_id proxy_out
      | None ->
        Logs.warn (fun m -> m "INCOMING: NO MSGDATA");
        Lwt.return_unit
    end
    >>= fun () -> return @@ `Established
  | `Ok (_ , `Response resp , `Data msg) ->
    let _ = resp , msg in (*TODO*)
    Lwt.return (`Fatal "TLS EOF or ALERT")
  | `Fail (failure , `Response resp) ->
    let _ = resp in (*TODO*)
    Lwt.return @@ `Fatal (Printf.sprintf "TLS FAIL: %s"
                          @@ Tls.Engine.string_of_failure failure)
  end

let handle_resend_ack ~proxy_out ~conn_id ~acked_seq ~next_seq =
  (* TODO update next_seq *)
  Logs.debug (fun m -> m "[%ld] %a Got a request to resend seq %Ld, next: %Ld"
                 conn_id Fmt.(styled_unit `Underline "RESEND") ()
                 acked_seq next_seq) ;
  let conn_state = Hashtbl.find states conn_id in (*TODO handle not found?*)
  begin match conn_state.tls_state.encryptor with
    | Some encryptor ->
      if acked_seq < next_seq && encryptor.sequence <= next_seq then
        (*conn_state.tls_state <- {tls_state with
              encryptor = Some {encryptor with sequence = next_seq}} ;*)
        let line =
          let rec rec_l = function
            | [] -> failwith "TODO line to be resent doesn't exist\n"
            | (s, m) :: _ when s = acked_seq -> m
            | _ :: tl -> rec_l tl
          in rec_l conn_state.outgoing
        in
        begin match encrypt_queue conn_state.tls_state [line] next_seq with
          | Error _ -> return @@ `Fatal
              (Printf.sprintf "resend, but error re-encrypting \
                               TODO die ns:%Ld" next_seq)
          | Ok (tls_state , msg_list) ->
            conn_state.tls_state <- tls_state ;
            let msgs = List.map (fun (resent_seq, cout) ->
                serialize_outgoing conn_id resent_seq
                @@ Cstruct.to_string cout)
                msg_list
            in
            (*TODO reinject into outgoing queue and clear old entry *)
            conn_state.outgoing <- (next_seq ,
                                    line) :: conn_state.outgoing ;
            Hashtbl.replace states conn_id conn_state ;
            Lwt_io.write proxy_out String.(concat "" msgs)
            >>= fun () -> send_pings_if_needed conn_id proxy_out
            >>= fun () -> return @@ `Established
        end
      else
        Lwt.return @@ `Fatal
          (Printf.sprintf
             "TODO was asked to resend, but acked %Ld ; \
              next %Ld ; current encryptor.seq %Ld"
             acked_seq next_seq encryptor.sequence)
    | None ->
      Lwt.return @@ `Fatal "resend, but no connection TODO die"
  end

let handle_irc_client client_in client_out target proxy_details certs =
  connect_proxy client_out proxy_details certs >>= function
  | Error err ->
    Logs.err (fun m -> m "err: %s" err) ; Lwt.return_unit
  | Ok (proxy_in, proxy_out) ->
    Logs.debug (fun m -> m "connected to proxy") ;

    (* We are connected to the proxy, ask for current status to identify
       the case where we need to reconnect to an existing connection: *)
    Lwt_io.write proxy_out (serialize_status 0l Int32.max_int) >>= fun () ->

    let string_of_state = function
      | `Initial_status_answer -> "Initial_status_answer"
      | `Handle_connect_response -> "Handle_connect_response"
      | `Established -> "Established"
    and fatal msg = return (`Fatal msg)
    in

    let rec loop ~state needed_len acc =
      Logs.debug (fun m -> m "entering loop - %d" needed_len) ;
      Lwt_io.read ~count:needed_len proxy_in >>= fun msg ->
      if "" = msg then fatal "handle_irc_client->loop: connection closed TODO"
      else
        let msg = String.concat "" [acc ; msg] in
        let decoded_msg = unserialized_of_server_msg msg in
        Logs.debug (fun m -> m "%a" pp_server_message decoded_msg);
        begin match state , decoded_msg with
          | _ , `Need_more count ->
            loop ~state count msg

          | _ , `Invalid _ ->
            fatal @@ "Failed to decode received data in state "
                     ^ (string_of_state state)

          | (`Initial_status_answer, (`Connect_answer _
                                     |`Incoming _|`Outgoing_ACK _))
          | (`Established, `Connect_answer _)
          | (`Handle_connect_response, (`Incoming _
                                       |`Outgoing_ACK _|`Status_answer _))
            ->  (* Handle invalid combinations of (state , received msg): *)
            fatal @@ "invalid (parseable) msg received in state "
                     ^ (string_of_state state) ^ "received: " ^ msg

          | `Initial_status_answer , `Status_answer (ans:status_answer list) ->
            Lwt_list.iter_s
              (function ({conn_id ; ping_interval ; address ; port;
                         seq_num ; count_queued}:status_answer) ->
                 if (target:Socks.socks4_request).address = address
                 && target.port = port
                 then begin
                   Logs.warn (fun m ->
                       m "FOUND EXISTING CONNECTION FOR SAME HOST \
                          conn_id: %ld ping int: %d address: %s port: %d \
                          seq_num: %Ld queued pings: %ld"
                         conn_id ping_interval address port seq_num
                         count_queued) ;
                   Lwt.return_unit
                     (* need to decrypt or supply tls engine state:
                        Hashtbl.replace states { tls_state = Tls.Engine.state ;
                        outgoing = [] ;
                        address ; port ; max_covered_sequence } *)
                 end else begin
                   Logs.warn (fun m ->
                       m "existing connection: %ld ping interval: %d \
                          address: %s port: %d seq_num: %Ld \
                          count_queued: %ld"
                         conn_id ping_interval address port seq_num
                         count_queued) ;
                   Lwt.return_unit
                 end
              )
              ans >>= fun () ->
            (*TODO: only if we don't have an existing state: *)
            (* Ask the proxy to connect to target.address: *)
            let target : Socks.socks4_request = target in
            begin match Tlsping.serialize_connect 20
                          (target.address, target.port) with
              | None ->
                Logs.err (fun m ->
                    m "error: unable to serialize connect to \
                       '%s':%d" target.address target.port) ;
                Lwt.return_unit
              | Some connect_msg ->
                Lwt_io.write proxy_out connect_msg
            end
            >>= fun () -> return `Handle_connect_response

          (* Handle response to our CONNECT message: *)
          | `Handle_connect_response , `Connect_answer (conn_id , _ , _)
            when conn_id = 0l -> (* if failed *)
            fatal @@ Printf.sprintf "error from proxy: no connect to \
                                     %s" target.address
          (*TODO kill connection*)
          | `Handle_connect_response , `Connect_answer (conn_id , _ , _) ->
            Logs.debug (fun m -> m "=> Connect_answer conn_id %ld" conn_id) ;
            (* Initialize TLS connection from client -> target *)
            let authenticator : X509.Authenticator.t =
              (* Do this dance instead of using X509_lwt.authenticator to
                 allow using expired certificates as long as the key fp
                 is correct: *)
              (fun ?host certificate_list ->
                 match List.map (fun c -> X509.Certificate.validity c |> snd)
                         certificate_list with
                 | [] -> Error `EmptyCertificateChain
                 | first::_ as expiry_list ->
                   let time = List.fold_left (fun acc than ->
                       if Ptime.is_earlier acc ~than
                       then acc else than) first expiry_list in
                   match Ptime.sub_span time (Ptime.Span.of_int_s 1) with
                   | Some time ->
                     X509.Validation.trust_key_fingerprint ?host ~time
                       ~hash:`SHA256
                       ~fingerprints:[
                         Domain_name.of_string_exn (target.address),
                         Hex.to_cstruct (`Hex target.username)]
                       certificate_list
                   | None -> Error `InvalidChain
                   (* shouldn't happen unless a cert has has expiry
                      at Ptime epoch, which it shouldn't have. *)
              ) in
            return @@ Tls.Config.client
              ~authenticator
              ~ciphers:[ `TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
                       ; `TLS_DHE_RSA_WITH_AES_256_CBC_SHA ]
              ~version:Tls.Core.(TLS_1_2 , TLS_1_2) (* g *)
              ~hashes:[`SHA256 ; `SHA1] ()
            >>= fun tls_config ->
            return @@ Tls.Engine.client tls_config
            >>= fun (tls_state, client_hello) ->
            (* Initiate a TLS connection: *)
            Hashtbl.add states conn_id {tls_state; outgoing = [] ;
                                        address = target.address ;
                                        port = target.port ;
                                        max_covered_sequence = 0L } ;
            Lwt_io.write proxy_out (serialize_outgoing conn_id 0L
                                      Cstruct.(to_string client_hello)
                                   ) >>= fun () ->
            (* setup thread that encrypts outgoing messages by proxy *)
            Lwt.async (handle_outgoing conn_id client_in proxy_out) ;
            return @@ `Established

          | `Established , `Incoming (conn_id , next_seq , queued_seq , msg) ->
            handle_incoming ~proxy_out ~client_out ~conn_id ~next_seq
              ~queued_seq ~msg

          | `Established , `Outgoing_ACK (conn_id ,
                                          `Ok ,
                                          acked_seq ,
                                          _next_seq) ->
            let conn_state = Hashtbl.find states conn_id in (*TODO handle not found?*)
            (* message was sent; remove it from local buffer *)
            let outgoing =
              let rec f acc = function
                | (s , _ ) :: tl when -1 = Int64.compare s acked_seq ->
                  f acc tl
                | hd :: tl -> f (hd::acc) tl
                | [] -> List.rev acc
              in f [] conn_state.outgoing
            in
            conn_state.outgoing <- outgoing ;
            Hashtbl.replace states conn_id conn_state ;
            Logs.warn (fun m -> m "outgoing ack: TODO cleanup buffers") ;
            return `Established

          | `Established , `Outgoing_ACK (conn_id ,
                                          `Resend ,
                                          acked_seq ,
                                          next_seq) ->
            handle_resend_ack ~proxy_out ~conn_id ~acked_seq ~next_seq

          | `Established , `Status_answer _lst ->
            Logs.debug (fun m -> m "%a"
                           Fmt.(styled `Cyan @@ styled_unit `Underline "Status_answer") ()) ;
            return `Established

    end (* begin match state_machine *)
    >>= function
    | (`Established | `Handle_connect_response) as new_state ->
      loop ~state:(new_state) 2 ""
    | fatal -> return fatal
  in
  begin loop ~state:`Initial_status_answer 2 "" >>= function
  | `Fatal msg ->
      Logs.err (fun m -> m "%s" msg) ; Lwt.return_unit
  | _ ->
      failwith "TODO unhandled exit state\n"
  end

(*
let handle_client (unix_fd, sockaddr) proxy certs () =
  begin match sockaddr with
  | Lwt_unix.ADDR_INET ( _ (*inet_addr*), port) ->
    Logs.debug (fun m -> m "Incoming connection, src port: %d" port) ;
    Lwt.return_unit
  | Lwt_unix.ADDR_UNIX _ -> return ()
  end >>= fun () ->
  let client_in  = Lwt_io.of_fd ~mode:Input  unix_fd
  and client_out = Lwt_io.of_fd ~mode:Output unix_fd in
  Socks.receive_request client_in >>= function
  | `Invalid_fingerprint fp ->
    Logs.err (fun m -> m "socks4 handler: invalid sha256 fingerprint: %s"
                 fp) ; Lwt.return_unit (* TODO cancel this *)
  | `Invalid_request ->
    Logs.err (fun m -> m "invalid request!") ;
    Lwt.fail (Invalid_argument "invalid request!") (*TODO failwith / logging *)
  | `Socks4 ({Socks.port ; username; address } as target) ->
    Logs.debug (fun m -> m "got request for host '%s' port %d fp %s"
      address port username) ;
    handle_irc_client client_in client_out target proxy certs
*)

let socks_request_policy _server_fingerprint _TODO_proxy_and_certs
  : 'a Socks_lwt.request_policy =
  fun req ->
    let open Lwt_result in
  begin match req with
  | `Socks4 req -> Lwt_result.return (req.address, req.port)
  | `Socks5 Connect { address = Domain_address addr ; port } ->
    Lwt_result.return (addr, port)
  | _ -> Lwt_result.fail (`Msg "bad socks conn type")
  end >>= fun (addr,port) ->
  (* TODO make socks able to let us specify a custom setup function *)
  let cb : Socks_lwt.client_data_cb =
    (fun _data _channel -> Lwt.return_unit)
  in
  let open Lwt_result in
  Lwt_result.ok (Lwt.return cb)

let socks5_auth_policy proxy_and_certs : ('a,'b) Socks_lwt.auth_policy =
  let validate_fp username =
    (* tlsping uses the "user_id" field in socks4 to hold the hex-encoded
       sha256 fingerprint of the x509 certificate of address:port
    *)
    if 64 <> String.length username
    then Error (`Invalid_fingerprint username)
    else try Ok (Hex.of_string username) with _ ->
      Error (`Invalid_fingerprint username)
  in
  fun lst ->
  if List.exists (function Socks.Username_password _ -> true
                         | _ -> false) lst
  then Lwt_result.return
      (Socks.Username_password ("",""),
       (function
         | Socks.Username_password (username, _) ->
           begin match validate_fp username with
             | Ok fp ->
               Lwt_result.return (socks_request_policy fp proxy_and_certs)
             | _ -> Lwt_result.fail (`Msg "")
           end
         | _ -> Lwt_result.fail (`Msg "TODO")
       ))
  else Lwt_result.fail (`Msg "Not using username-password auth")

let socks_address_policy proxy_and_certs : ('a,'b,'c) Socks_lwt.address_policy =
  Socks_lwt.client_allow_localhost (socks5_auth_policy proxy_and_certs)

let listener_service (host,port) proxy_and_certs =
  let open Lwt_unix in
  create_socket host >>= function
  | Error () -> failwith "unable to resolve listen addr"
  | Ok (s , host_inet_addr) ->
  Lwt_unix.close s >>= fun () ->
  (*   let () = listen s 10 in TODO *)
  (*(Lwt.async (handle_client c proxy certs) ;*)
  let server = Socks_lwt.establish_server (ADDR_INET (host_inet_addr, port ))
      (socks_address_policy proxy_and_certs) in
  server

let run_client () listen_host listen_port proxy_host proxy_port
    ca_public_cert client_public_cert client_secret_key =
  let listen = (listen_host , listen_port) in
  let proxy  = (proxy_host  , proxy_port) in
  let certs  = ca_public_cert , client_public_cert , client_secret_key in
  Lwt_main.run (listener_service listen (proxy,certs))

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
  Arg.(value & opt (int) (6667) & info ["listen-port";"lport"]
         ~docv:"LISTEN-PORT"
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
     ~doc:"The client public certificate file used to \
           authenticate to the proxy")

let client_secret_key =
  Arg.(required & pos 3 (some string) None & info []
      ~docv:"CLIENT-SECRET-KEY"
      ~doc:"The client secret key file belonging to this client")

let setup_log =
  let _setup_log (style_renderer:Fmt.style_renderer option) level : unit =
    Fmt_tty.setup_std_outputs ?style_renderer () ;
    Logs.set_level level ;
    Logs.set_reporter (Logs_fmt.reporter ())
  in
  Term.(const _setup_log $ Fmt_cli.style_renderer ()
                        $ Logs_cli.level ())

let cmd =
  let doc = "TLS ping client" in
  let man = [
    `S "DESCRIPTION" ;
    `P "$(tname) connects to a TLS ping proxy server" ;
    `S "BUGS" ;
    `P "Please report bugs on the issue tracker at <https://github.com/cfcs/tlsping/issues>" ;
    `S "SEE ALSO" ;
    `P "<https://github.com/cfcs/tlspingd/blob/master/readme.md>" ]
  in
  Term.(pure run_client $ setup_log
        $ listen_host $ listen_port $ proxy_host $ proxy_port $ ca_public_cert
        $ client_public_cert $ client_secret_key ),
  Term.info "tls_ping_client" ~version:"0.1.0" ~doc ~man

let () =
  (* TODO Lwt_daemon.daemonize + Lwt_daemon.logger *)
  match Term.eval cmd with
  | `Error _ -> exit 1
  | _ -> exit 0
