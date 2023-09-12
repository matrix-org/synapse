## Admin FAQ

How do I become a server admin?
---
If your server already has an admin account you should use the
[User Admin API](../../admin_api/user_admin_api.md#change-whether-a-user-is-a-server-administrator-or-not)
to promote other accounts to become admins.

If you don't have any admin accounts yet you won't be able to use the admin API,
so you'll have to edit the database manually. Manually editing the database is
generally not recommended so once you have an admin account: use the admin APIs
to make further changes.

```sql
UPDATE users SET admin = 1 WHERE name = '@foo:bar.com';
```

What servers are my server talking to?
---
Run this sql query on your db:
```sql
SELECT * FROM destinations;
```

What servers are currently participating in this room?
---
Run this sql query on your db:
```sql
SELECT DISTINCT split_part(state_key, ':', 2)
FROM current_state_events
WHERE room_id = '!cURbafjkfsMDVwdRDQ:matrix.org' AND membership = 'join';
```

What users are registered on my server?
---
```sql
SELECT NAME from users;
```

How can I export user data?
---
Synapse includes a Python command to export data for a specific user. It takes the homeserver
configuration file and the full Matrix ID of the user to export:

```console
python -m synapse.app.admin_cmd -c <config_file> export-data <user_id> --output-directory <directory_path>
```

If you uses [Poetry](../../development/dependencies.md#managing-dependencies-with-poetry)
to run Synapse:

```console
poetry run python -m synapse.app.admin_cmd -c <config_file> export-data <user_id> --output-directory <directory_path>
```

The directory to store the export data in can be customised with the
`--output-directory` parameter; ensure that the provided directory is
empty. If this parameter is not provided, Synapse defaults to creating
a temporary directory (which starts with "synapse-exfiltrate") in `/tmp`,
`/var/tmp`, or `/usr/tmp`, in that order.

The exported data has the following layout:

```
output-directory
├───rooms
│   └───<room_id>
│       ├───events
│       ├───state
│       ├───invite_state
│       └───knock_state
├───user_data
│   ├───account_data
│   │   ├───global
│   │   └───<room_id>
│   ├───connections
│   ├───devices
│   └───profile
└───media_ids
    └───<media_id>
```

The `media_ids` folder contains only the metadata of the media uploaded by the user.
It does not contain the media itself.
Furthermore, only the `media_ids` that Synapse manages itself are exported.
If another media repository (e.g. [matrix-media-repo](https://github.com/turt2live/matrix-media-repo))
is used, the data must be exported separately.

With the `media_ids` the media files can be downloaded.
Media that have been sent in encrypted rooms are only retrieved in encrypted form.
The following script can help with download the media files:

```bash
#!/usr/bin/env bash

# Parameters
#
#   source_directory: Directory which contains the export with the media_ids.
#   target_directory: Directory into which all files are to be downloaded.
#   repository_url: Address of the media repository resp. media worker.
#   serverName: Name of the server (`server_name` from homeserver.yaml).
#
#   Example:
#       ./download_media.sh /tmp/export_data/media_ids/ /tmp/export_data/media_files/ http://localhost:8008 matrix.example.com

source_directory=$1
target_directory=$2
repository_url=$3
serverName=$4

mkdir -p $target_directory

for file in $source_directory/*; do
    filename=$(basename ${file})
    url=$repository_url/_matrix/media/v3/download/$serverName/$filename
    echo "Downloading $filename - $url"
    if ! wget -o /dev/null -P $target_directory $url; then
        echo "Could not download $filename"
    fi
done
```

Manually resetting passwords
---
Users can reset their password through their client. Alternatively, a server admin
can reset a user's password using the [admin API](../../admin_api/user_admin_api.md#reset-password).


I have a problem with my server. Can I just delete my database and start again?
---
Deleting your database is unlikely to make anything better.

It's easy to make the mistake of thinking that you can start again from a clean
slate by dropping your database, but things don't work like that in a federated
network: lots of other servers have information about your server.

For example: other servers might think that you are in a room, your server will
think that you are not, and you'll probably be unable to interact with that room
in a sensible way ever again.

In general, there are better solutions to any problem than dropping the database.
Come and seek help in https://matrix.to/#/#synapse:matrix.org.

There are two exceptions when it might be sensible to delete your database and start again:
* You have *never* joined any rooms which are federated with other servers. For
instance, a local deployment which the outside world can't talk to.
* You are changing the `server_name` in the homeserver configuration. In effect
this makes your server a completely new one from the point of view of the network,
so in this case it makes sense to start with a clean database.
(In both cases you probably also want to clear out the media_store.)

I've stuffed up access to my room, how can I delete it to free up the alias?
---
Using the following curl command:
```console
curl -H 'Authorization: Bearer <access-token>' -X DELETE https://matrix.org/_matrix/client/r0/directory/room/<room-alias>
```
`<access-token>` - can be obtained in riot by looking in the riot settings, down the bottom is:
Access Token:\<click to reveal\>

`<room-alias>` - the room alias, eg. #my_room:matrix.org this possibly needs to be URL encoded also, for example  %23my_room%3Amatrix.org

How can I find the lines corresponding to a given HTTP request in my homeserver log?
---

Synapse tags each log line according to the HTTP request it is processing. When
it finishes processing each request, it logs a line containing the words
`Processed request: `. For example:

```
2019-02-14 22:35:08,196 - synapse.access.http.8008 - 302 - INFO - GET-37 - ::1 - 8008 - {@richvdh:localhost} Processed request: 0.173sec/0.001sec (0.002sec, 0.000sec) (0.027sec/0.026sec/2) 687B 200 "GET /_matrix/client/r0/sync HTTP/1.1" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Safari/537.36" [0 dbevts]"
```

Here we can see that the request has been tagged with `GET-37`. (The tag depends
on the method of the HTTP request, so might start with `GET-`, `PUT-`, `POST-`,
`OPTIONS-` or `DELETE-`.) So to find all lines corresponding to this request, we can do:

```console
grep 'GET-37' homeserver.log
```

If you want to paste that output into a github issue or matrix room, please
remember to surround it with triple-backticks (```) to make it legible
(see [quoting code](https://help.github.com/en/articles/basic-writing-and-formatting-syntax#quoting-code)).


What do all those fields in the 'Processed' line mean?
---
See [Request log format](request_log.md).


What are the biggest rooms on my server?
---

```sql
SELECT s.canonical_alias, g.room_id, count(*) AS num_rows
FROM
  state_groups_state AS g,
  room_stats_state AS s
WHERE g.room_id = s.room_id
GROUP BY s.canonical_alias, g.room_id
ORDER BY num_rows desc
LIMIT 10;
```

You can also use the [List Room API](../../admin_api/rooms.md#list-room-api)
and `order_by` `state_events`.


People can't accept room invitations from me
---

The typical failure mode here is that you send an invitation to someone
to join a room or direct chat, but when they go to accept it, they get an
error (typically along the lines of "Invalid signature"). They might see
something like the following in their logs:

    2019-09-11 19:32:04,271 - synapse.federation.transport.server - 288 - WARNING - GET-11752 - authenticate_request failed: 401: Invalid signature for server <server> with key ed25519:a_EqML: Unable to verify signature for <server>

This is normally caused by a misconfiguration in your reverse-proxy. See [the reverse proxy docs](../../reverse_proxy.md) and double-check that your settings are correct.


Help!! Synapse is slow and eats all my RAM/CPU!
---

First, ensure you are running the latest version of Synapse, using Python 3
with a [PostgreSQL database](../../postgres.md).

Synapse's architecture is quite RAM hungry currently - we deliberately
cache a lot of recent room data and metadata in RAM in order to speed up
common requests. We'll improve this in the future, but for now the easiest
way to either reduce the RAM usage (at the risk of slowing things down)
is to set the almost-undocumented ``SYNAPSE_CACHE_FACTOR`` environment
variable. The default is 0.5, which can be decreased to reduce RAM usage
in memory constrained environments, or increased if performance starts to
degrade.

However, degraded performance due to a low cache factor, common on
machines with slow disks, often leads to explosions in memory use due
backlogged requests. In this case, reducing the cache factor will make
things worse. Instead, try increasing it drastically. 2.0 is a good
starting value.

Using [libjemalloc](https://jemalloc.net) can also yield a significant
improvement in overall memory use, and especially in terms of giving back
RAM to the OS. To use it, the library must simply be put in the
LD_PRELOAD environment variable when launching Synapse. On Debian, this
can be done by installing the `libjemalloc1` package and adding this
line to `/etc/default/matrix-synapse`:

    LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libjemalloc.so.1

This made a significant difference on Python 2.7 - it's unclear how
much of an improvement it provides on Python 3.x.

If you're encountering high CPU use by the Synapse process itself, you
may be affected by a bug with presence tracking that leads to a
massive excess of outgoing federation requests (see [discussion](https://github.com/matrix-org/synapse/issues/3971)). If metrics
indicate that your server is also issuing far more outgoing federation
requests than can be accounted for by your users' activity, this is a
likely cause. The misbehavior can be worked around by disabling presence
in the Synapse config file: [see here](../configuration/config_documentation.md#presence).


Running out of File Handles
---

If Synapse runs out of file handles, it typically fails badly - live-locking
at 100% CPU, and/or failing to accept new TCP connections (blocking the
connecting client).  Matrix currently can legitimately use a lot of file handles,
thanks to busy rooms like `#matrix:matrix.org` containing hundreds of participating
servers.  The first time a server talks in a room it will try to connect
simultaneously to all participating servers, which could exhaust the available
file descriptors between DNS queries & HTTPS sockets, especially if DNS is slow
to respond. (We need to improve the routing algorithm used to be better than
full mesh, but as of March 2019 this hasn't happened yet).

If you hit this failure mode, we recommend increasing the maximum number of
open file handles to be at least 4096 (assuming a default of 1024 or 256).
This is typically done by editing ``/etc/security/limits.conf``

Separately, Synapse may leak file handles if inbound HTTP requests get stuck
during processing - e.g. blocked behind a lock or talking to a remote server etc.
This is best diagnosed by matching up the 'Received request' and 'Processed request'
log lines and looking for any 'Processed request' lines which take more than
a few seconds to execute. Please let us know at [`#synapse:matrix.org`](https://matrix.to/#/#synapse-dev:matrix.org) if
you see this failure mode so we can help debug it, however.
