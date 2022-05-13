User Directory API Implementation
=================================

The user directory is currently maintained based on the 'visible' users
on this particular server - i.e. ones which your account shares a room with, or
who are present in a publicly viewable room present on the server.

The directory info is stored in various tables, which can (typically after
DB corruption) get stale or out of sync. If this happens, for now the
solution to fix it is to use the [admin API](usage/administration/admin_api/background_updates.md#run)
and execute the job `regenerate_directory`. This should then start a background task to
flush the current tables and regenerate the directory.

Data model
----------

There are five relevant tables that collectively form the "user directory".
Three of them track a master list of all the users we could search for.
The last two (collectively called the "search tables") track who can
see who.

From all of these tables we exclude three types of local user:
  - support users
  - appservice users
  - deactivated users

* `user_directory`. This contains the user_id, display name and avatar we'll
  return when you search the directory.
  - Because there's only one directory entry per user, it's important that we only
    ever put publicly visible names here. Otherwise we might leak a private
    nickname or avatar used in a private room.
  - Indexed on rooms. Indexed on users.

* `user_directory_search`. To be joined to `user_directory`. It contains an extra
  column that enables full text search based on user ids and display names.
  Different schemas for SQLite and Postgres with different code paths to match.
  - Indexed on the full text search data. Indexed on users.

* `user_directory_stream_pos`. When the initial background update to populate
  the directory is complete, we record a stream position here. This indicates
  that synapse should now listen for room changes and incrementally update
  the directory where necessary.

* `users_in_public_rooms`. Contains associations between users and the public rooms they're in.
  Used to determine which users are in public rooms and should be publicly visible in the directory.

* `users_who_share_private_rooms`. Rows are triples `(L, M, room id)` where `L`
   is a local user and `M` is a local or remote user. `L` and `M` should be
   different, but this isn't enforced by a constraint.
