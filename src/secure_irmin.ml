open Lwt
open Sexplib.Std

module Opaque
    (Store : Irmin.RW with type key = string list and type value = string)
= struct
  let location = ["secure_log"]

  let entry_type = Cstruct.create 0

  let get_log t =
    Store.read t location
    >>= fun result ->
    match result with
    | None -> assert false
    | Some s ->
      sexp_of_string s
      |> Secure_log.log_of_sexp
      |> Lwt.return

  let append t value =
    get_log t
    >>= fun log ->
    let log' =
      Secure_log.append entry_type value log
    in
    Store.update t location (Secure_log.sexp_of_log log' |> string_of_sexp)


  let validate t =
    get_log t
    >>= fun log ->
    Secure_log.validate log;
    Lwt.return_unit

end

module Visible
    (Store : Irmin.RW with type key = string list and type value = string)
= struct

  include Opaque (Store)

  let validate_macs t key =
    get_log t
    >>= fun log ->
    Secure_log.validate_macs log key;
    Lwt.return_unit

  let read t key entry =
    get_log t
    >>= fun log ->
    Secure_log.get_entry log key entry
    |> Lwt.return

end

open Lwt
open Sexplib.Std
open Printf

open Irmin_unix

module Store = Irmin_git.FS (Irmin.Contents.String) (Irmin.Tag.String) (Irmin.Hash.SHA1)



module Test = Opaque (Store)


let root = "/tmp/irmin/test"

let store = Irmin.basic (module Irmin_git.FS) (module Irmin.Contents.String)

let update t k v =
  let msg = sprintf "Updating /%s" (String.concat "/" k) in
  print_endline msg;
  Irmin.update (t msg) k v

let read_exn t k =
  let msg = sprintf "Reading /%s" (String.concat "/" k) in
  print_endline msg;
  Irmin.read_exn (t msg) k

let main () =
  let config = Irmin_git.config ~root ~bare:true () in
  Irmin.create store config task >>= fun t ->

  update t ["root";"misc";"1.txt"] "Hello world!" >>= fun () ->
  update t ["root";"misc";"2.txt"] "Hi!" >>= fun () ->
  update t ["root";"misc";"3.txt"] "How are you ?" >>= fun () ->
  read_exn t ["root";"misc";"2.txt"] >>= fun _ ->

  Irmin.clone_force task (t "x: Cloning 't'") "test" >>= fun x ->
  print_endline "cloning ...";

  update t ["root";"misc";"3.txt"] "Hohoho" >>= fun () ->
  update x ["root";"misc";"2.txt"] "Cool!"  >>= fun () ->

  Irmin.merge_exn "t: Merge with 'x'" x ~into:t >>= fun () ->
  print_endline "merging ...";

  read_exn t ["root";"misc";"2.txt"]  >>= fun _ ->
  read_exn t ["root";"misc";"3.txt"]  >>= fun _ ->

  return_unit

let () =
  Printf.printf
    "This example creates a Git repository in %s and use it to read \n\
     and write data:\n" root ;
  Lwt_unix.run (main ());
  Printf.printf
     "You can now run `cd %s && tig` to inspect the store.\n" root;
