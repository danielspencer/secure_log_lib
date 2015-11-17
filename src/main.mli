
type log

type entry

type entry_type

val append : entry_type -> Cstruct.t -> log-> log

val decrypt : entry -> Cstruct.t -> Cstruct.t
