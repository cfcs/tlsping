open Tls
open Rresult

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

