
type log with sexp

type entry with sexp

type entry_type = Cstruct.t

val new_log : Cstruct.t -> log

val append : entry_type -> Cstruct.t -> log-> log

val get_entries : log -> entry list

val decrypt : entry -> Cstruct.t -> Cstruct.t
