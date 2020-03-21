open Alcotest
open Tlsping
open Printf

let read_file filename =
    let ch = open_in filename in
    let s = really_input_string ch (in_channel_length ch) in
    close_in ch;
    s

let write_file filename str =
  let oc = open_out filename in
  Logs.debug (fun m -> m "wrote debug file");
  fprintf oc "%s" str;   
  close_out oc


let test_serialization () = 
  let ss1 = read_file "serialized_state.txt" in
  let state = deserialize_tls_state ss1 in
  let ss2 = serialize_tls_state ~sanity:false state in
  (check string) "serializing 1" ss1 ss2


(*  Alcotest.(check string) "items in map" "whtat is dit" serialized_state () *)


let () =
  let open Alcotest in

  run "Utils" [
      "map", [ test_case "serialization" `Quick test_serialization  ];
    ]
