# TCP Replication

## Motivation

Previously the workers used an HTTP long poll mechanism to get updates
from the master, which had the problem of causing a lot of duplicate
work on the server. This TCP protocol replaces those APIs with the aim
of increased efficiency.

## Overview

The protocol is based on fire and forget, line based commands. An
example flow would be (where '>' indicates master to worker and
'<' worker to master flows):

    > SERVER example.com
    < REPLICATE
    > POSITION events master 53 53
    > RDATA events master 54 ["$foo1:bar.com", ...]
    > RDATA events master 55 ["$foo4:bar.com", ...]

The example shows the server accepting a new connection and sending its identity
with the `SERVER` command, followed by the client server to respond with the
position of all streams. The server then periodically sends `RDATA` commands
which have the format `RDATA <stream_name> <instance_name> <token> <row>`, where
the format of `<row>` is defined by the individual streams. The
`<instance_name>` is the name of the Synapse process that generated the data
(usually "master").

Error reporting happens by either the client or server sending an ERROR
command, and usually the connection will be closed.

Since the protocol is a simple line based, its possible to manually
connect to the server using a tool like netcat. A few things should be
noted when manually using the protocol:

-   The federation stream is only available if federation sending has
    been disabled on the main process.
-   The server will only time connections out that have sent a `PING`
    command. If a ping is sent then the connection will be closed if no
    further commands are receieved within 15s. Both the client and
    server protocol implementations will send an initial PING on
    connection and ensure at least one command every 5s is sent (not
    necessarily `PING`).
-   `RDATA` commands *usually* include a numeric token, however if the
    stream has multiple rows to replicate per token the server will send
    multiple `RDATA` commands, with all but the last having a token of
    `batch`. See the documentation on `commands.RdataCommand` for
    further details.

## Architecture

The basic structure of the protocol is line based, where the initial
word of each line specifies the command. The rest of the line is parsed
based on the command. For example, the RDATA command is defined as:

    RDATA <stream_name> <instance_name> <token> <row_json>

(Note that <row_json> may contains spaces, but cannot contain
newlines.)

Blank lines are ignored.

### Keep alives

Both sides are expected to send at least one command every 5s or so, and
should send a `PING` command if necessary. If either side do not receive
a command within e.g. 15s then the connection should be closed.

Because the server may be connected to manually using e.g. netcat, the
timeouts aren't enabled until an initial `PING` command is seen. Both
the client and server implementations below send a `PING` command
immediately on connection to ensure the timeouts are enabled.

This ensures that both sides can quickly realize if the tcp connection
has gone and handle the situation appropriately.

### Start up

When a new connection is made, the server:

-   Sends a `SERVER` command, which includes the identity of the server,
    allowing the client to detect if its connected to the expected
    server
-   Sends a `PING` command as above, to enable the client to time out
    connections promptly.

The client:

-   Sends a `NAME` command, allowing the server to associate a human
    friendly name with the connection. This is optional.
-   Sends a `PING` as above
-   Sends a `REPLICATE` to get the current position of all streams.
-   On receipt of a `SERVER` command, checks that the server name
    matches the expected server name.

### Error handling

If either side detects an error it can send an `ERROR` command and close
the connection.

If the client side loses the connection to the server it should
reconnect, following the steps above.

### Congestion

If the server sends messages faster than the client can consume them the
server will first buffer a (fairly large) number of commands and then
disconnect the client. This ensures that we don't queue up an unbounded
number of commands in memory and gives us a potential oppurtunity to
squawk loudly. When/if the client recovers it can reconnect to the
server and ask for missed messages.

### Reliability

In general the replication stream should be considered an unreliable
transport since e.g. commands are not resent if the connection
disappears.

The exception to that are the replication streams, i.e. RDATA commands,
since these include tokens which can be used to restart the stream on
connection errors.

The client should keep track of the token in the last RDATA command
received for each stream so that on reconneciton it can start streaming
from the correct place. Note: not all RDATA have valid tokens due to
batching. See `RdataCommand` for more details.

### Example

An example iteraction is shown below. Each line is prefixed with '>'
or '<' to indicate which side is sending, these are *not* included on
the wire:

    * connection established *
    > SERVER localhost:8823
    > PING 1490197665618
    < NAME synapse.app.appservice
    < PING 1490197665618
    < REPLICATE
    > POSITION events master 1 1
    > POSITION backfill master 1 1
    > POSITION caches master 1 1
    > RDATA caches master 2 ["get_user_by_id",["@01register-user:localhost:8823"],1490197670513]
    > RDATA events master 14 ["$149019767112vOHxz:localhost:8823",
        "!AFDCvgApUmpdfVjIXm:localhost:8823","m.room.guest_access","",null]
    < PING 1490197675618
    > ERROR server stopping
    * connection closed by server *

The `POSITION` command sent by the server is used to set the clients
position without needing to send data with the `RDATA` command.

An example of a batched set of `RDATA` is:

    > RDATA caches master batch ["get_user_by_id",["@test:localhost:8823"],1490197670513]
    > RDATA caches master batch ["get_user_by_id",["@test2:localhost:8823"],1490197670513]
    > RDATA caches master batch ["get_user_by_id",["@test3:localhost:8823"],1490197670513]
    > RDATA caches master 54 ["get_user_by_id",["@test4:localhost:8823"],1490197670513]

In this case the client shouldn't advance their caches token until it
sees the the last `RDATA`.

### List of commands

The list of valid commands, with which side can send it: server (S) or
client (C):

#### SERVER (S)

   Sent at the start to identify which server the client is talking to

#### RDATA (S)

   A single update in a stream

#### POSITION (S)

   On receipt of a POSITION command clients should check if they have missed any
   updates, and if so then fetch them out of band. Sent in response to a
   REPLICATE command (but can happen at any time).

   The POSITION command includes the source of the stream. Currently all streams
   are written by a single process (usually "master"). If fetching missing
   updates via HTTP API, rather than via the DB, then processes should make the
   request to the appropriate process.

   Two positions are included, the "new" position and the last position sent respectively.
   This allows servers to tell instances that the positions have advanced but no
   data has been written, without clients needlessly checking to see if they
   have missed any updates.

#### ERROR (S, C)

   There was an error

#### PING (S, C)

   Sent periodically to ensure the connection is still alive

#### NAME (C)

   Sent at the start by client to inform the server who they are

#### REPLICATE (C)

Asks the server for the current position of all streams.

#### USER_SYNC (C)

   A user has started or stopped syncing on this process.

#### CLEAR_USER_SYNC (C)

   The server should clear all associated user sync data from the worker.

   This is used when a worker is shutting down.

#### FEDERATION_ACK (C)

   Acknowledge receipt of some federation data

### REMOTE_SERVER_UP (S, C)

   Inform other processes that a remote server may have come back online.

See `synapse/replication/tcp/commands.py` for a detailed description and
the format of each command.

### Cache Invalidation Stream

The cache invalidation stream is used to inform workers when they need
to invalidate any of their caches in the data store. This is done by
streaming all cache invalidations done on master down to the workers,
assuming that any caches on the workers also exist on the master.

Each individual cache invalidation results in a row being sent down
replication, which includes the cache name (the name of the function)
and they key to invalidate. For example:

    > RDATA caches master 550953771 ["get_user_by_id", ["@bob:example.com"], 1550574873251]

Alternatively, an entire cache can be invalidated by sending down a `null`
instead of the key. For example:

    > RDATA caches master 550953772 ["get_user_by_id", null, 1550574873252]

However, there are times when a number of caches need to be invalidated
at the same time with the same key. To reduce traffic we batch those
invalidations into a single poke by defining a special cache name that
workers understand to mean to expand to invalidate the correct caches.

Currently the special cache names are declared in
`synapse/storage/_base.py` and are:

1.  `cs_cache_fake` ─ invalidates caches that depend on the current
    state
