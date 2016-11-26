open Lwt
open Nocrypto
open Sexplib.Std

type view = ([`BC], string list, string) Irmin.t

exception Invalid_log

let hash_algo = `SHA256
module Cipher = Cipher_block.AES.CBC

type entry_ref = Cstruct.t option with sexp

type entry =
  { cipher_text : Cstruct.t
  ; prev_hash   : entry_ref
  ; hash        : Cstruct.t
  ; hash_mac    : Cstruct.t
  } with sexp

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
  if not (expected_size = Cstruct.len entry) then (
    Printf.printf
      "Expected %i from len %i and block %i, found %i\n"
      expected_size
      len
      block_size
      (Cstruct.len entry);
    Printexc.print_raw_backtrace stdout (Printexc.get_callstack 100);
    assert false
  );
  let v = Cstruct.create len in
  Cstruct.blit entry 4 v 0 len;
  v
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

let get_data_key key =
  Cstruct.concat
    [ Cstruct.of_string "Encryption Key"
    ; key
    ]
  |> Hash.digest hash_algo
  |> Cipher.of_secret

let produce_next prev_hash text ~key =
  let encryption_key =
    (*
    Cstruct.append (Cstruct.of_string "Create key") key
    |> Hash.digest hash_algo
    |>
       *)
    get_data_key key
  in
  let cipher_text =
    (* The initialisation vector isn't relevant due to the key only being used once *)
    (* TODO: check this assertion *)
    let iv = Cstruct.create (Cipher.block_size) in
    Cstruct.memset iv 0;
    Cipher.encrypt ~key:encryption_key ~iv (pad text ~block_size:Cipher.block_size)
  in
  let hash =
    next_hash prev_hash cipher_text
  in
  let hash_mac = Hash.mac hash_algo ~key hash in
  {cipher_text; hash; hash_mac; prev_hash}

module Shared
    (Base : sig
       type t
       val view : t -> view
       val prefix : t -> string list
     end)
= struct

  let prefix t key = List.append (Base.prefix t) key

  let key_of_hash t hash =
    let `Hex name =
      Hex.of_cstruct hash
    in
    prefix t [name]

  let head = ["head"]

  let get_head_ref t =
    Irmin.read_exn (Base.view t) (prefix t head)
    >|= fun head_ref ->
    Sexplib.Sexp.of_string head_ref |> entry_ref_of_sexp

  let read_entry t hash =
    Irmin.read_exn (Base.view t) (key_of_hash t hash)
    >|= fun str ->
    let entry =
      Sexplib.Sexp.of_string str |> entry_of_sexp
    in
    if not (Cstruct.equal entry.hash hash) then
      raise Invalid_log;
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
    get_entries t >|= fun entries ->
    List.iter
      (fun entry ->
         let expected_hash = next_hash entry.prev_hash entry.cipher_text in
         if not (Cstruct.equal expected_hash entry.hash) then
           raise Invalid_log
      )
      entries

end


module Client
= struct
  type t = { view : view ; prefix : string list ; key_loc : string}

  include Shared
      (struct
        type nonrec t = t
        let view t = t.view
        let prefix t = t.prefix
      end)

  let create view prefix key_loc =
    { view; prefix; key_loc }

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

  let write_head t ref =
    Irmin.update
      t.view
      (prefix t head)
      (sexp_of_entry_ref ref |> Sexplib.Sexp.to_string)

  let initialise t key =
    write_key t key
    >>= fun () ->
    write_head t None

  let write_entry t entry =
    Irmin.update
      t.view
      (key_of_hash t entry.hash)
      (sexp_of_entry entry |> Sexplib.Sexp.to_string)
    >>= fun () ->
    write_head t (Some entry.hash)


  let append t text =
    get_head_ref t
    >>= fun head_ref ->
    read_key t
    >>= fun key ->
    let next =
      produce_next head_ref text ~key
    in
    let write_progress =
      write_entry t next
    in
    let next_key = next_key key in
    let key_progress =
      write_key t next_key
    in
    write_progress <&> key_progress

end

module Intermediary = struct
  type t = { view : view ; prefix : string list }
  include Shared
      (struct
        type nonrec t = t
        let view t = t.view
        let prefix t = t.prefix
      end)

  let create view prefix = {view; prefix}
end

module Server
= struct
  type t = { view : view ; prefix : string list ; meta_loc : string}

  include Shared
      (struct
        type nonrec t = t
        let view t = t.view
        let prefix t = t.prefix
      end)

  type meta = { init_key : Cstruct.t ; last_hash : entry_ref ; next_key : Cstruct.t } with sexp

  let create view prefix meta_loc =
    { view; prefix; meta_loc }

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
           if not (Cstruct.equal expected_hash entry.hash) then
             raise Invalid_log;
           let expected_mac =
             Hash.mac hash_algo ~key entry.hash
           in
           if not (Cstruct.equal expected_mac entry.hash_mac) then
             raise Invalid_log;
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
    List.fold_left
      (fun key entry ->
         let expected_hash = next_hash entry.prev_hash entry.cipher_text in
         if not (Cstruct.equal expected_hash entry.hash) then
           raise Invalid_log;
         let expected_mac =
           Hash.mac hash_algo ~key entry.hash
         in
         if not (Cstruct.equal expected_mac entry.hash_mac) then
           raise Invalid_log;
         next_key key
      )
      meta.init_key
      entries
    |> ignore;
    return_unit

  let dump_log t =
    get_entries t >>= fun entries ->
    read_meta t >>= fun meta ->
    List.fold_left
      (fun (key,logs) entry ->
         let encryption_key =
           get_data_key key
         in
         let iv = Cstruct.create (Cipher.block_size) in
         Cstruct.memset iv 0;
         let str =
           Cipher.decrypt ~key:encryption_key ~iv entry.cipher_text
           |> unpad ~block_size:Cipher.block_size
         in
         next_key key, str::logs
      )
      (meta.init_key,[])
      entries
    |> snd |> List.rev
    |> List.iteri
      (fun i str -> Printf.printf "%i: %s\n" i (Cstruct.to_string str));
    return_unit

end

