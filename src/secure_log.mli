
type log with sexp

type entry with sexp

type key with sexp

val key_of_cstruct : Cstruct.t -> key
val cstruct_of_key : key -> Cstruct.t

val pad : Cstruct.t -> block_size:int -> Cstruct.t
val unpad : Cstruct.t -> block_size:int -> Cstruct.t

type entry_type = Cstruct.t

val new_log : key -> log
val reconstruct : key -> entry list -> log

val append : entry_type -> Cstruct.t -> log -> log

val get_entry : log -> key -> int -> Cstruct.t
val decrypt_all : log -> key -> Cstruct.t list

val get_entries : log -> entry list
val get_key : log -> key

val decrypt : entry -> key -> Cstruct.t

exception Invalid_log

val validate : entry list -> unit
val validate_macs : log -> key -> unit
