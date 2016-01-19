open Lwt
open Sexplib.Std

module Opaque
    (Store : Irmin.RW with type key = string list and type value = string)
= struct
  let location = ["secure_log"]

  let entry_type = Cstruct.create 0

  let get_entries t =
    Store.read t location
    >>= fun result ->
    match result with
    | None -> assert false
    | Some s ->
      sexp_of_string s
      |> list_of_sexp Secure_log.entry_of_sexp
      |> Lwt.return

  let get_log t head_key =
    get_entries t
    >>= fun entries ->
    Secure_log.reconstruct head_key entries
    |> Lwt.return

  let append t head_key value =
    get_log t head_key
    >>= fun log ->
    let log' =
      Secure_log.append entry_type value log
    in
    let entries =
      Secure_log.get_entries log'
    in
    Store.update
      t
      location
      (sexp_of_list Secure_log.sexp_of_entry entries |> string_of_sexp)


  let validate t =
    get_entries t
    >>= fun entries ->
    Secure_log.validate entries;
    Lwt.return_unit

end

module Visible
    (Store : Irmin.RW with type key = string list and type value = string)
= struct

  include Opaque (Store)

  let validate_macs t base_key =
    get_log t base_key
    >>= fun entries ->
    Secure_log.validate_macs entries base_key;
    Lwt.return_unit

  let read t base_key entry =
    get_log t base_key
    >>= fun log ->
    Secure_log.get_entry log base_key entry
    |> Lwt.return

end

