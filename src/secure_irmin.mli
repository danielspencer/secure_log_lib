
module Opaque :
functor
  (Store : Irmin.RW with type key = string list and type value = string) ->
  sig
    val location : string list
    val entry_type : Cstruct.t
    val get_entries : Store.t -> Secure_log.entry list Lwt.t
    val get_log : Store.t -> Secure_log.key -> Secure_log.log Lwt.t
    val append : Store.t -> Secure_log.key -> Cstruct.t -> unit Lwt.t
    val validate : Store.t -> unit Lwt.t
  end

(* Should Visible be separate from Opaque? Consider merging them *)
module Visible :
functor
  (Store : Irmin.RW with type key = string list and type value = string) ->
  sig
    include module type of Opaque (Store)
    val validate_macs : Store.t -> Secure_log.key -> unit Lwt.t
    val read : Store.t -> Secure_log.key -> int -> Cstruct.t Lwt.t
  end
