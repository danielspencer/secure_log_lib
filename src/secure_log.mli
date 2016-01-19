
type log with sexp

type entry with sexp

type key with sexp

val key_of_cstruct : Cstruct.t -> key

val pad : Cstruct.t -> block_size:int -> Cstruct.t
val unpad : Cstruct.t -> block_size:int -> Cstruct.t

type entry_type = Cstruct.t

val new_log : key -> log

val append : entry_type -> Cstruct.t -> log-> log

val get_entry : log -> key -> int -> Cstruct.t

val get_entries : log -> entry list

val decrypt : entry -> key -> Cstruct.t

val validate : log -> unit
val validate_macs : log -> key -> unit
