# User Directory API Implementation

The user directory is maintained based on the 'visible' users of a homeserver -
i.e. ones which are local to the server, ones which a local user shares a room
with, or ones who are present in a publicly viewable room present on the server.

The directory info is stored in various tables, which can sometimes get out of
sync (although this is considered a bug). If this happens, for now the
solution to fix it is to use the [admin API](usage/administration/admin_api/background_updates.md#run)
and execute the job `regenerate_directory`. This should then start a background task to
flush the current tables and regenerate the directory. Depending on the size
of your homeserver (number of users and rooms) this can take a while.

## Data model

There are five relevant tables that collectively form the "user directory".
Three of them track a list of all known users. The last two (collectively called
the "search tables") track which users are visible to each other.

From all of these tables we exclude three types of local user:

- support users
- appservice users
- deactivated users

A description of each table follows:

* `user_directory`. This contains the user ID, display name and avatar of each user.
  - Because there is only one directory entry per user, it is important that it
    only contain publicly visible information. Otherwise, this will leak the
    nickname or avatar used in a private room.
  - Indexed on rooms. Indexed on users.

* `user_directory_search`. To be joined to `user_directory`. It contains an extra
  column that enables full text search based on user IDs and display names.
  Different schemas for SQLite and Postgres are used.
  - Indexed on the full text search data. Indexed on users.

* `user_directory_stream_pos`. When the initial background update to populate
  the directory is complete, we record a stream position here. This indicates
  that synapse should now listen for room changes and incrementally update
  the directory where necessary.

* `users_in_public_rooms`. Contains associations between users and the public
  rooms they're in.  Used to determine which users are in public rooms and should
  be publicly visible in the directory.

* `users_who_share_private_rooms`. Rows are triples `(L, M, room id)` where `L`
   is a local user and `M` is a local or remote user. `L` and `M` should be
   different, but this isn't enforced by a constraint.

   Note that if two local users share a room then there will be two entries:
   `(user1, user2, !room_id)` and `(user2, user1, !room_id)`.

## Configuration options

The exact way user search works can be tweaked via some server-level
[configuration options](usage/configuration/config_documentation.md#user_directory).

The information is not repeated here, but the options are mentioned below.

## Search algorithm

### PostgreSQL

TODO

### SQLite

TODO
