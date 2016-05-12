open Lwt
open Nocrypto
open Sexplib.Std

let hash_algo = `SHA256
module Cipher = Cipher_block.AES.CBC

type entry_ref = Cstruct.t option with sexp

type entry =
  { cipher_text : Cstruct.t
  ; prev_hash   : entry_ref
  ; hash        : Cstruct.t
  ; hash_mac    : Cstruct.t
  } with sexp

let next_key key =
    Cstruct.append (Cstruct.of_string "Increment Hash") key
    |> Hash.digest hash_algo

let next_hash prev_hash cipher_text =
  let prev_hash = match prev_hash with
    | Some hash -> hash
    | None ->
      let blank = Cstruct.create 20 in
      Cstruct.memset blank 0; blank
  in
  Cstruct.append prev_hash cipher_text
  |> Hash.digest hash_algo

let produce_next prev_hash text ~key =
  let encryption_key =
    Cipher.of_secret key
  in
  let cipher_text =
    (* The initialisation vector isn't relevant due to the key only being used once *)
    (* TODO: check this assertion *)
    let iv = Cstruct.create (Cipher.block_size) in
    Cstruct.memset iv 0;
    Cipher.encrypt ~key:encryption_key ~iv (Secure_log.pad text ~block_size:Cipher.block_size)
  in
  let hash =
    next_hash prev_hash cipher_text
  in
  let hash_mac = Hash.mac hash_algo ~key hash in
  {cipher_text; hash; hash_mac; prev_hash}


module Opaque
    (View : Irmin.VIEW with type key = string list and type value = string)
= struct

  type t = { view : View.t ; key_loc : string}

  let create view key_loc =
    { view; key_loc }

  let head = ["head"]

  let key_of_hash hash =
    let name =
      Hex.of_cstruct hash |> Hex.to_string
    in
    [name]

  let read_key t =
    Lwt_io.with_file
      ~flags:[Unix.O_RDONLY]
      ~mode:Lwt_io.input
      t.key_loc
      (fun channel ->
         Lwt_io.read channel
         >|= Cstruct.of_string)

  let write_key t key =
    Lwt_io.with_file
      ~flags:[Unix.O_CREAT; Unix.O_TRUNC; Unix.O_WRONLY]
      ~mode:Lwt_io.output
      t.key_loc
      (fun channel ->
         let str =
           Cstruct.to_string key
         in
         Lwt_io.write channel str)

  let write_entry t entry =
    View.update
      t.view
      (key_of_hash entry.hash)
      (sexp_of_entry entry |> Sexplib.Sexp.to_string)

  let get_head_ref t =
    View.read_exn t.view head
    >|= fun head_ref ->
    Sexplib.Sexp.of_string head_ref |> entry_ref_of_sexp

  let read_entry t hash =
    View.read_exn t.view (key_of_hash hash)
    >|= fun str ->
    let entry =
      Sexplib.Sexp.of_string str |> entry_of_sexp
    in
    assert (Cstruct.equal entry.hash hash);
    entry

  let append t text =
    get_head_ref t
    >>= fun head_ref ->
    read_key t
    >>= fun key ->
    let next =
      produce_next head_ref text ~key
    in
    write_entry t next

  let get_entries t =
    get_head_ref t
    >>= fun head ->
    let rec aux ref acc =
      match ref with
      | Some hash ->
        read_entry t hash
        >>= fun entry ->
        aux entry.prev_hash (entry::acc)
      | None -> return acc
    in
    aux head []

  let validate t =
    get_entries t >|= fun entries ->
    List.iter
      (fun entry ->
         let expected_hash = next_hash entry.prev_hash entry.cipher_text in
         assert (Cstruct.equal expected_hash entry.hash))
      entries

end

module Visible
    (View : Irmin.VIEW with type key = string list and type value = string)
= struct

  type t = { view : View.t ; meta_loc : string}

  type meta = { init_key : Cstruct.t ; last_hash : entry_ref ; next_key : Cstruct.t } with sexp

  let create view meta_loc =
    { view; meta_loc }

  let head = ["head"]

  let key_of_hash hash =
    let name =
      Hex.of_cstruct hash |> Hex.to_string
    in
    [name]

  let read_meta t =
    Lwt_io.with_file
      ~flags:[Unix.O_RDONLY]
      ~mode:Lwt_io.input
      t.meta_loc
      (fun channel ->
         Lwt_io.read channel
         >|= fun str ->
         Sexplib.Sexp.of_string str
         |> meta_of_sexp
      )

  let write_meta t meta =
    Lwt_io.with_file
      ~flags:[Unix.O_CREAT; Unix.O_TRUNC; Unix.O_WRONLY]
      ~mode:Lwt_io.output
      t.meta_loc
      (fun channel ->
         let str =
           sexp_of_meta meta |> Sexplib.Sexp.to_string
         in
         Lwt_io.write channel str)

  let get_head_ref t =
    View.read_exn t.view head
    >|= fun head_ref ->
    Sexplib.Sexp.of_string head_ref |> entry_ref_of_sexp

  let read_entry t hash =
    View.read_exn t.view (key_of_hash hash)
    >|= fun str ->
    let entry =
      Sexplib.Sexp.of_string str |> entry_of_sexp
    in
    assert (Cstruct.equal entry.hash hash);
    entry

  let get_entries t =
    get_head_ref t
    >>= fun head ->
    let rec aux ref acc =
      match ref with
      | Some hash ->
        read_entry t hash
        >>= fun entry ->
        aux entry.prev_hash (entry::acc)
      | None -> return acc
    in
    aux head []

  let validate t =
    (* This probably should be removed? *)
    get_entries t >|= fun entries ->
    List.iter
      (fun entry ->
         let expected_hash = next_hash entry.prev_hash entry.cipher_text in
         assert (Cstruct.equal expected_hash entry.hash))
      entries

  let option_equal equal opt1 opt2 =
    match opt1, opt2 with
    | None, None -> true
    | None, _ | _, None -> false
    | Some s1, Some s2 -> equal s1 s2

  let incremental_validate t =
    read_meta t >>= fun meta ->
    get_head_ref t
    >>= fun head ->
    let rec aux ref acc =
      match ref, meta.last_hash with
      | r1, r2 when option_equal Cstruct.equal r1 r2 -> return acc
      | Some hash, _ ->
        read_entry t hash
        >>= fun entry ->
        aux entry.prev_hash (entry::acc)
      | None, _ -> fail (Failure "Reached last entry without finding last validated entry")
    in
    aux head []
    >>= fun entries ->
    let next_key =
      List.fold_right
        (fun entry key ->
           let expected_hash = next_hash entry.prev_hash entry.cipher_text in
           assert (Cstruct.equal expected_hash entry.hash);
           let expected_mac =
             Hash.mac hash_algo ~key entry.hash
           in
           assert (Cstruct.equal expected_mac entry.hash_mac);
           next_key key)
        entries
        meta.next_key
    in
    let last_hash = head in
    let meta = {meta with next_key; last_hash} in
    write_meta t meta


  let validate_macs t =
    get_entries t >>= fun entries ->
    read_meta t >>= fun meta ->
    List.fold_right
      (fun entry key ->
         let expected_hash = next_hash entry.prev_hash entry.cipher_text in
         assert (Cstruct.equal expected_hash entry.hash);
         let expected_mac =
           Hash.mac hash_algo ~key entry.hash
         in
         assert (Cstruct.equal expected_mac entry.hash_mac);
         next_key key
      )
      entries
      meta.init_key
    |> ignore;
    return_unit

  let dump_log t =
    get_entries t >>= fun entries ->
    read_meta t >>= fun meta ->
    List.fold_right
      (fun entry (key,logs) ->
         let encryption_key =
           Cipher.of_secret key
         in
         let iv = Cstruct.create (Cipher.block_size) in
         Cstruct.memset iv 0;
         let str =
           Cipher.decrypt ~key:encryption_key ~iv entry.cipher_text
           |> Secure_log.unpad ~block_size:Cipher.block_size
         in
         next_key key, str::logs
      )
      entries
      (meta.init_key,[])
    |> snd |> List.rev
    |> List.iteri
      (fun i str -> Printf.printf "%i: %s\n" i (Cstruct.to_string str));
    return_unit

end

