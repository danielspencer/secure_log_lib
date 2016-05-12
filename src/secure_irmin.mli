
module Opaque :
functor
  (View : Irmin.VIEW with type key = string list and type value = string) ->
  sig
    type t
    val create   : View.t -> string -> t
    val append   : t -> Cstruct.t -> unit Lwt.t
    val validate : t -> unit Lwt.t
  end

module Visible :
functor
  (View : Irmin.VIEW with type key = string list and type value = string) ->
  sig
    type t
    val create               : View.t -> string -> t
    val incremental_validate : t -> unit Lwt.t
    val validate_macs        : t -> unit Lwt.t
    val dump_log             : t -> unit Lwt.t
  end
