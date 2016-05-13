type view = ([`BC], string list, string) Irmin.t

exception Invalid_log

module Client :
  sig
    type t
    val create     : view -> string list -> string -> t
    val initialise : t -> Cstruct.t -> unit Lwt.t
    val append     : t -> Cstruct.t -> unit Lwt.t
    val validate   : t -> unit Lwt.t
  end

module Server :
  sig
    type t
    val create               : view -> string list -> string -> t
    val incremental_validate : t -> unit Lwt.t
    val validate_macs        : t -> unit Lwt.t
    val dump_log             : t -> unit Lwt.t
  end
