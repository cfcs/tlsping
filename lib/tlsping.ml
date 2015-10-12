type client_operation =
| Connect
| Outgoing
| Queue
| Ack
| Status
| Fetch
| Subscribe

type server_operation =
| Connect_answer
| Status_answer
| Incoming

type tls_config = {
  authenticator : X509.Authenticator.a
; ciphers : Tls.Ciphersuite.ciphersuite list
; version : Tls.Core.tls_version * Tls.Core.tls_version
; hashes  : Nocrypto.Hash.hash list
; certificates : Tls.Config.own_cert
}

let tls_config (ca_public_cert , public_cert , secret_key) =
  let open Lwt in
  X509_lwt.authenticator (`Ca_file ca_public_cert) >>= fun authenticator ->
  X509_lwt.private_of_pems ~cert:public_cert ~priv_key:secret_key >>= fun cert ->
  return {
    authenticator
  ; ciphers = Tls.Config.Ciphers.supported
  ; version = Tls.Core.(TLS_1_2,TLS_1_2)
  ; hashes  = [`SHA256]
  ; certificates = (`Single cert)
  }
    (*TODO restrict, put config in shared file*)

