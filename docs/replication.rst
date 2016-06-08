Replication Architecture
========================

Motivation
----------

We'd like to be able to split some of the work that synapse does into multiple
python processes. In theory multiple synapse processes could share a single
postgresql database and we'd scale up by running more synapse processes.
However much of synapse assumes that only one process is interacting with the
database, both for assigning unique identifiers when inserting into tables,
notifying components about new updates, and for invalidating its caches.

So running multiple copies of the current code isn't an option. One way to
run multiple processes would be to have a single writer process and multiple
reader processes connected to the same database. In order to do this we'd need
a way for the reader process to invalidate its in-memory caches when an update
happens on the writer. One way to do this is for the writer to present an
append-only log of updates which the readers can consume to invalidate their
caches and to push updates to listening clients or pushers.

Synapse already stores much of its data as an append-only log so that it can
correctly respond to /sync requests so the amount of code changes needed to
expose the append-only log to the readers should be fairly minimal.

Architecture
------------

The Replication API
~~~~~~~~~~~~~~~~~~~

Synapse will optionally expose a long poll HTTP API for extracting updates. The
API will have a similar shape to /sync in that clients provide tokens
indicating where in the log they have reached and a timeout. The synapse server
then either responds with updates immediately if it already has updates or it
waits until the timeout for more updates. If the timeout expires and nothing
happened then the server returns an empty response.

However unlike the /sync API this replication API is returning synapse specific
data rather than trying to implement a matrix specification. The replication
results are returned as arrays of rows where the rows are mostly lifted
directly from the database. This avoids unnecessary JSON parsing on the server
and hopefully avoids an impedance mismatch between the data returned and the
required updates to the datastore.

This does not replicate all the database tables as many of the database tables
are indexes that can be recovered from the contents of other tables.

The format and parameters for the api are documented in
``synapse/replication/resource.py``.


The Slaved DataStore
~~~~~~~~~~~~~~~~~~~~

There are read-only version of the synapse storage layer in
``synapse/replication/slave/storage`` that use the response of the replication
API to invalidate their caches.
