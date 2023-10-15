# Replication Architecture

## Motivation

We'd like to be able to split some of the work that synapse does into
multiple python processes. In theory multiple synapse processes could
share a single postgresql database and we\'d scale up by running more
synapse processes. However much of synapse assumes that only one process
is interacting with the database, both for assigning unique identifiers
when inserting into tables, notifying components about new updates, and
for invalidating its caches.

So running multiple copies of the current code isn't an option. One way
to run multiple processes would be to have a single writer process and
multiple reader processes connected to the same database. In order to do
this we'd need a way for the reader process to invalidate its in-memory
caches when an update happens on the writer. One way to do this is for
the writer to present an append-only log of updates which the readers
can consume to invalidate their caches and to push updates to listening
clients or pushers.

Synapse already stores much of its data as an append-only log so that it
can correctly respond to `/sync` requests so the amount of code changes
needed to expose the append-only log to the readers should be fairly
minimal.

## Architecture

### The Replication Protocol

See [the TCP replication documentation](tcp_replication.md).

### The TCP Replication Module
Information about how the tcp replication module is structured, including how
the classes interact, can be found in
`synapse/replication/tcp/__init__.py`
