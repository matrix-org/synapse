# User Directory API Implementation

The user directory is maintained based on users that are 'visible' to the homeserver -
i.e. ones which are local to the server and ones which any local user shares a
room with.

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
  the directory where necessary. (See [stream positions](development/synapse_architecture/streams.html).)

* `users_in_public_rooms`. Contains associations between users and the public
  rooms they're in.  Used to determine which users are in public rooms and should
  be publicly visible in the directory. Both local and remote users are tracked.

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

If `search_all_users` is `false`, then results are limited to users who:

1. Are found in the `users_in_public_rooms` table, or
2. Are found in the `users_who_share_private_rooms` where `L` is the requesting
   user and `M` is the search result.

Otherwise, if `search_all_users` is `true`, no such limits are placed and all
users known to the server (matching the search query) will be returned.

By default, locked users are not returned. If `show_locked_users` is `true` then
no filtering on the locked status of a user is done.

The user provided search term is lowercased and normalized using [NFKC](https://en.wikipedia.org/wiki/Unicode_equivalence#Normalization),
this treats the string as case-insensitive, canonicalizes different forms of the
same text, and maps some "roughly equivalent" characters together.

The search term is then split into words:

* If [ICU](https://en.wikipedia.org/wiki/International_Components_for_Unicode) is
  available, then the system's [default locale](https://unicode-org.github.io/icu/userguide/locale/#default-locales)
  will be used to break the search term into words. (See the
  [installation instructions](setup/installation.md) for how to install ICU.)
* If unavailable, then runs of ASCII characters, numbers, underscores, and hyphens
  are considered words.

The queries for PostgreSQL and SQLite are detailed below, by their overall goal
is to find matching users, preferring users who are "real" (e.g. not bots,
not deactivated). It is assumed that real users will have an display name and
avatar set.

### PostgreSQL

The above words are then transformed into two queries:

1. "exact" which matches the parsed words exactly (using [`to_tsquery`](https://www.postgresql.org/docs/current/textsearch-controls.html#TEXTSEARCH-PARSING-QUERIES));
2. "prefix" which matches the parsed words as prefixes (using `to_tsquery`).

Results are composed of all rows in the `user_directory_search` table whose information
matches one (or both) of these queries. Results are ordered by calculating a weighted
score for each result, higher scores are returned first:

* 4x if a user ID exists.
* 1.2x if the user has a display name set.
* 1.2x if the user has an avatar set.
* 0x-3x by the full text search results using the [`ts_rank_cd` function](https://www.postgresql.org/docs/current/textsearch-controls.html#TEXTSEARCH-RANKING)
  against the "exact" search query; this has four variables with the following weightings:
  * `D`: 0.1 for the user ID's domain
  * `C`: 0.1 for unused
  * `B`: 0.9 for the user's display name (or an empty string if it is not set)
  * `A`: 0.1 for the user ID's localpart
* 0x-1x by the full text search results using the `ts_rank_cd` function against the
  "prefix" search query. (Using the same weightings as above.)
* If `prefer_local_users` is `true`, then 2x if the user is local to the homeserver.

Note that `ts_rank_cd` returns a weight between 0 and 1. The initial weighting of
all results is 1.

### SQLite

Results are composed of all rows in the `user_directory_search` whose information
matches the query. Results are ordered by the following information, with each
subsequent column used as a tiebreaker, for each result:

1. By the [`rank`](https://www.sqlite.org/windowfunctions.html#built_in_window_functions)
   of the full text search results using the [`matchinfo` function](https://www.sqlite.org/fts3.html#matchinfo). Higher
   ranks are returned first.
2. If `prefer_local_users` is `true`, then users local to the homeserver are
   returned first.
3. Users with a display name set are returned first.
4. Users with an avatar set are returned first.
