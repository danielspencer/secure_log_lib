open Nocrypto
open Sexplib.Std

type key = K of Cstruct.t with sexp

let key_of_cstruct v = K v
let cstruct_of_key (K v) = v

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

let previous_hash entries =
  match entries with
  | hd::_ -> hd.hash
  | [] -> Cstruct.create 20

let next_key key =
    Cstruct.append (Cstruct.of_string "Increment Hash") (cstruct_of_key key)
    |> Hash.digest hash_algo
    |> key_of_cstruct

let rec nth_key key n =
  match n with
  | 0 -> key
  | n when (n > 0) -> nth_key (next_key key) (n - 1)
  | _ -> failwith "Cannot get negative keys"

let get_data_key key entry_type =
  Cstruct.concat
    [ Cstruct.of_string "Encryption Key"
    ; entry_type
    ; (cstruct_of_key key)
    ]
  |> Hash.digest hash_algo

let next_hash prev_hash cipher_text entry_type =
    Cstruct.concat
      [ prev_hash
      ; cipher_text
      ; entry_type
      ]
    |> Hash.digest hash_algo

let padded_size len block_size =
  let internal_len = len + 4 in
  let padding =
    if internal_len mod block_size = 0
    then 0
    else block_size - (internal_len mod block_size)
  in
  internal_len + padding

let pad entry ~block_size =
  let len = Cstruct.len entry in
  let external_len = padded_size len block_size in
  let v = Cstruct.create external_len in
  Cstruct.LE.set_uint32 v 0 (len |> Int32.of_int);
  (* [blit src srcoff dst dstoff len] *)
  Cstruct.blit entry 0 v 4 (Cstruct.len entry);
  v

let unpad entry ~block_size =
  let len = Cstruct.LE.get_uint32 entry 0 |> Int32.to_int in
  let expected_size = padded_size len block_size in
  assert (expected_size = Cstruct.len entry);
  let v = Cstruct.create len in
  Cstruct.blit entry 4 v 0 len;
  v

let append entry_type entry log =
  let key = log.key in
  let encryption_key =
    get_data_key key entry_type
    |> Cipher.of_secret
  in
  let cipher_text =
    (* The initialisation vector isn't relevant due to the key only being used once *)
    let iv = Cstruct.create (Cipher.block_size) in
    Cipher.encrypt ~key:encryption_key ~iv (pad entry ~block_size:Cipher.block_size)
  in
  let prev_hash = previous_hash log.entries in
  let hash =
    next_hash prev_hash cipher_text entry_type
  in
  let hash_mac = Hash.mac hash_algo ~key:(cstruct_of_key key) hash in
  let new_entry = {entry_type; cipher_text; hash; hash_mac} in
  let key' = next_key key in
  {key = key'; entries = new_entry::log.entries}

let decrypt entry key =
  let encryption_key =
    get_data_key key entry.entry_type |> Cipher.of_secret
  in
  let iv = Cstruct.create (Cipher.block_size) in
  Cipher.decrypt ~key:encryption_key ~iv entry.cipher_text
  |> unpad ~block_size:Cipher.block_size

let new_log key =
  {key; entries=[]}

let reconstruct key entries =
  {key; entries}

let get_entries log =
  log.entries

let get_key log =
  log.key

let get_entry log key n =
  let entries = log.entries in
  let len = List.length entries in
  let entry = List.nth entries (len - n - 1) in
  let key' = nth_key key n in
  decrypt entry key'

(* untested, possibly broken *)
let decrypt_all log key =
  let entries = List.rev log.entries in
  List.fold_right
    (fun entry (key, entries) -> (next_key key, decrypt entry key :: entries))
    entries
    (key, [])
  |> snd

let validate entries =
  let rec loop = function
    | [] -> ()
    | entry :: tail ->
      let prev = previous_hash tail in
      let expected = next_hash prev entry.cipher_text entry.entry_type in
      assert (Cstruct.equal expected entry.hash);
      loop tail
  in
  loop entries

let validate_macs log key =
  let entries = log.entries in
  let rec loop key = function
    | [] -> ()
    | entry :: tail ->
      let expected = Hash.mac hash_algo ~key:(cstruct_of_key key) entry.hash in
      assert (Cstruct.equal entry.hash_mac expected);
      loop (next_key key) tail
  in
  loop key (List.rev entries)
