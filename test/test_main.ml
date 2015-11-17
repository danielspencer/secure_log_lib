open OUnit

let test_encrypt_decrypt _ =
  let open Main in
  let key = Cstruct.of_string "key" in
  let entry_type = Cstruct.create 1 in
  let empty = new_log key in
  let str = "data data dataaa" in
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

let suite =
  "OUnit Example" >:::
  [ "test_encrypt_decrypt" >:: test_encrypt_decrypt
  ]

let _ =
  run_test_tt_main suite
