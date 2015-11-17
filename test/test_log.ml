open OUnit

open Nocrypto
module Cipher = Cipher_block.AES.CBC
let hash_algo = `SHA256

let test_pad _ =
  let open Log in
  let str = "data data dataaaaaa" |> Cstruct.of_string in
  let block_size = 16 in
  let pad_cycled =
    pad str ~block_size |> unpad ~block_size
  in
  assert (str = pad_cycled)

let test_cycle _ =
  let open Log in
  List.iter (fun str ->
      let entry = Cstruct.of_string str in
      let key =
        Cstruct.of_string "keys!"
        |> Hash.digest hash_algo
        |> Cipher.of_secret
      in
      let iv = Cstruct.create (Cipher.block_size) in
      let out =
        Cipher.encrypt ~key ~iv (pad entry ~block_size:Cipher.block_size)
        |> Cipher.decrypt ~key ~iv
        |> unpad ~block_size:Cipher.block_size
      in
      assert (Cstruct.equal entry out))
    [ "asdf"
    ; "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    ; "42"
    ; Bytes.create 90
    ]


let test_encrypt_decrypt_once _ =
  let open Log in
  let key =
    Cstruct.of_string "key"
    |> key_of_cstruct
  in
  let entry_type = Cstruct.create 1 in
  let empty = new_log key in
  let str = "data data dataaaaaa" in
  let data = (Cstruct.of_string str) in
  let one_entry =
    append entry_type data empty
  in
  let decrypted =
    decrypt (List.hd (get_entries one_entry)) key
    |> Cstruct.to_string
  in
  assert_equal decrypted str
    (*
  if not (decrypted = str) then
    failwith (Printf.sprintf "Strings don't match: %s\n%s\n" str decrypted)
  else
    print_string "Strings matched"
       *)

let test_enc_dec_list _ =
  let open Log in
  let key =
    Cstruct.of_string "key"
    |> key_of_cstruct
  in
  let entry_type = Cstruct.create 1 in
  let empty = new_log key in
  let strs =
    [ "data data dataaaaaa"
    ; "WOOP!"
    ; "42"
    ]
  in
  let log =
    List.fold_left
      (fun log str ->
        let data = (Cstruct.of_string str) in
        append entry_type data log)
      empty
      strs
  in
  List.iteri
    (fun i str ->
       assert
         (Cstruct.equal
            (Cstruct.of_string str)
            (get_entry log key i)))
    strs

let test_validate _ =
  let open Log in
  let key =
    Cstruct.of_string "key"
    |> key_of_cstruct
  in
  let entry_type = Cstruct.create 1 in
  let empty = new_log key in
  let strs =
    [ "data data dataaaaaa"
    ; "WOOP!"
    ; "42"
    ]
  in
  let log =
    List.fold_left
      (fun log str ->
        let data = (Cstruct.of_string str) in
        append entry_type data log)
      empty
      strs
  in
  validate log;
  validate_macs log key


let suite =
  "Test main secure log features" >:::
  [ "test_pad"                  >:: test_pad
  ; "test_cycle"                >:: test_cycle
  ; "test_encrypt_decrypt_once" >:: test_encrypt_decrypt_once
  ; "test_enc_dec_list"         >:: test_enc_dec_list
  ; "test_validate"             >:: test_validate
  ]

let _ =
  run_test_tt_main suite
