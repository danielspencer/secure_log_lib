open Nocrypto
open Sexplib.Std

type key = Cstruct.t with sexp

type entry_type = Cstruct.t with sexp

let hash_algo = `SHA256
module Cipher = Cipher_block.AES.CBC

(* Cstruct.ts, Cstruct.ts everywhere *)
type entry =
  { entry_type  : entry_type
  ; cipher_text : Cstruct.t
  ; hash        : Cstruct.t
  ; hash_mac    : Cstruct.t
  } with sexp

type log =
  { key     : key
  ; entries : entry list
  } with sexp

let previous_hash log =
  match log.entries with
  | hd::_ -> hd.hash
  | [] -> Cstruct.create 20

let next_key key =
    Cstruct.append (Cstruct.of_string "Increment Hash") key
    |> Hash.digest hash_algo

let get_data_key key entry_type =
  Cstruct.concat
    [ Cstruct.of_string "Encryption Key"
    ; entry_type
    ; key
    ]
  |> Hash.digest hash_algo

let next_hash prev_hash cipher_text entry_type =
    Cstruct.concat
      [ prev_hash
      ; cipher_text
      ; entry_type
      ]
    |> Hash.digest hash_algo

let append entry_type entry log =
  let key = log.key in
  let encryption_key =
    get_data_key key entry_type
    |> Cipher.of_secret
  in
  let cipher_text =
    (* The initialisation vector isn't relevant due to the key only being used once *)
    let iv = Cstruct.create (Cipher.block_size) in
    Cipher.encrypt ~key:encryption_key ~iv entry
  in
  let prev_hash = previous_hash log in
  let hash =
    next_hash prev_hash cipher_text entry_type
  in
  let hash_mac = Hash.mac hash_algo ~key hash in
  let new_entry = {entry_type; cipher_text; hash; hash_mac} in
  let key' = next_key key in
  {key = key'; entries = new_entry::log.entries}

let decrypt entry key =
  let encryption_key =
    get_data_key key entry.entry_type |> Cipher.of_secret
  in
  let iv = Cstruct.create (Cipher.block_size) in
  Cipher.decrypt ~key:encryption_key ~iv entry.cipher_text

let new_log key =
  {key; entries=[]}

let get_entries log =
  log.entries
