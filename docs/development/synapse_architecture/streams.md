## Streams

Synapse has a concept of "streams", which are roughly described in [`id_generators.py`](
    https://github.com/matrix-org/synapse/blob/develop/synapse/storage/util/id_generators.py
).
Generally speaking, streams are a series of notifications that something in Synapse's database has changed that the application might need to respond to.
For example:

- The events stream reports new events (PDUs) that Synapse creates, or that Synapse accepts from another homeserver.
- The account data stream reports changes to users' [account data](https://spec.matrix.org/v1.7/client-server-api/#client-config).
- The to-device stream reports when a device has a new [to-device message](https://spec.matrix.org/v1.7/client-server-api/#send-to-device-messaging).

See [`synapse.replication.tcp.streams`](
    https://github.com/matrix-org/synapse/blob/develop/synapse/replication/tcp/streams/__init__.py
) for the full list of streams.

It is very helpful to understand the streams mechanism when working on any part of Synapse that needs to respond to changes—especially if those changes are made by different workers.
To that end, let's describe streams formally, paraphrasing from the docstring of [`AbstractStreamIdGenerator`](
    https://github.com/matrix-org/synapse/blob/a719b703d9bd0dade2565ddcad0e2f3a7a9d4c37/synapse/storage/util/id_generators.py#L96
).

### Definition

A stream is an append-only log `T1, T2, ..., Tn, ...` of facts[^1] which grows over time.
Only "writers" can add facts to a stream, and there may be multiple writers.

Each fact has an ID, called its "stream ID".
Readers should only process facts in ascending stream ID order.

Roughly speaking, each stream is backed by a database table.
It should have a `stream_id` (or similar) bigint column holding stream IDs, plus additional columns as necessary to describe the fact.
Typically, a fact is expressed with a single row in its backing table.[^2]
Within a stream, no two facts may have the same stream_id.

> _Aside_. Some additional notes on streams' backing tables.
>
> 1. Rich would like to [ditch the backing tables](https://github.com/matrix-org/synapse/issues/13456).
> 2. The backing tables may have other uses.
     >    For example, the events table serves backs the events stream, and is read when processing new events.
     >    But old rows are read from the table all the time, whenever Synapse needs to lookup some facts about an event.
> 3. Rich suspects that sometimes the stream is backed by multiple tables, so the stream proper is the union of those tables.

Stream writers can "reserve" a stream ID, and then later mark it as having being completed.
Stream writers need to track the completion of each stream fact.
In the happy case, completion means a fact has been written to the stream table.
But unhappy cases (e.g. transaction rollback due to an error) also count as completion.
Once completed, the rows written with that stream ID are fixed, and no new rows
will be inserted with that ID.

### Current stream ID

For any given stream reader (including writers themselves), we may define a per-writer current stream ID:

> A current stream ID _for a writer W_ is the largest stream ID such that
> all transactions added by W with equal or smaller ID have completed.

Similarly, there is a "linear" notion of current stream ID:

> A "linear" current stream ID is the largest stream ID such that
> all facts (added by any writer) with equal or smaller ID have completed.

Because different stream readers A and B learn about new facts at different times, A and B may disagree about current stream IDs.
Put differently: we should think of stream readers as being independent of each other, proceeding through a stream of facts at different rates.

The above definition does not give a unique current stream ID, in fact there can
be a range of current stream IDs. Synapse uses both the minimum and maximum IDs
for different purposes. Most often the maximum is used, as its generally
beneficial for workers to advance their IDs as soon as possible. However, the
minimum is used in situations where e.g. another worker is going to wait until
the stream advances past a position.

**NB.** For both senses of "current", that if a writer opens a transaction that never completes, the current stream ID will never advance beyond that writer's last written stream ID.

For single-writer streams, the per-writer current ID and the linear current ID are the same.
Both senses of current ID are monotonic, but they may "skip" or jump over IDs because facts complete out of order.


_Example_.
Consider a single-writer stream which is initially at ID 1.

| Action     | Current stream ID | Notes                                           |
|------------|-------------------|-------------------------------------------------|
|            | 1                 |                                                 |
| Reserve 2  | 1                 |                                                 |
| Reserve 3  | 1                 |                                                 |
| Complete 3 | 1                 | current ID unchanged, waiting for 2 to complete |
| Complete 2 | 3                 | current ID jumps from 1 -> 3                    |
| Reserve 4  | 3                 |                                                 |
| Reserve 5  | 3                 |                                                 |
| Reserve 6  | 3                 |                                                 |
| Complete 5 | 3                 |                                                 |
| Complete 4 | 5                 | current ID jumps 3->5, even though 6 is pending |
| Complete 6 | 6                 |                                                 |


### Multi-writer streams

There are two ways to view a multi-writer stream.

1. Treat it as a collection of distinct single-writer streams, one
   for each writer.
2. Treat it as a single stream.

The single stream (option 2) is conceptually simpler, and easier to represent (a single stream id).
However, it requires each reader to know about the entire set of writers, to ensures that readers don't erroneously advance their current stream position too early and miss a fact from an unknown writer.
In contrast, multiple parallel streams (option 1) are more complex, requiring more state to represent (map from writer to stream id).
The payoff for doing so is that readers can "peek" ahead to facts that completed on one writer no matter the state of the others, reducing latency.

Note that a multi-writer stream can be viewed in both ways.
For example, the events stream is treated as multiple single-writer streams (option 1) by the sync handler, so that events are sent to clients as soon as possible.
But the background process that works through events treats them as a single linear stream.

Another useful example is the cache invalidation stream.
The facts this stream holds are instructions to "you should now invalidate these cache entries".
We only ever treat this as a multiple single-writer streams as there is no important ordering between cache invalidations.
(Invalidations are self-contained facts; and the invalidations commute/are idempotent).

### Writing to streams

Writers need to track:
 - track their current position (i.e. its own per-writer stream ID).
 - their facts currently awaiting completion.

At startup,
 - the current position of that writer can be found by querying the database (which suggests that facts need to be written to the database atomically, in a transaction); and
 - there are no facts awaiting completion.

To reserve a stream ID, call [`nextval`](https://www.postgresql.org/docs/current/functions-sequence.html) on the appropriate postgres sequence.

To write a fact to the stream: insert the appropriate rows to the appropriate backing table.

To complete a fact, first remove it from your map of facts currently awaiting completion.
Then, if no earlier fact is awaiting completion, the writer can advance its current position in that stream.
Upon doing so it should emit an `RDATA` message[^3], once for every fact between the old and the new stream ID.

### Subscribing to streams

Readers need to track the current position of every writer.

At startup, they can find this by contacting each writer with a `REPLICATE` message,
requesting that all writers reply describing their current position in their streams.
Writers reply with a `POSITION` message.

To learn about new facts, readers should listen for `RDATA` messages and process them to respond to the new fact.
The `RDATA` itself is not a self-contained representation of the fact;
readers will have to query the stream tables for the full details.
Readers must also advance their record of the writer's current position for that stream.

# Summary

In a nutshell: we have an append-only log with a "buffer/scratchpad" at the end where we have to wait for the sequence to be linear and contiguous.


---

[^1]: we use the word _fact_ here for two reasons.
Firstly, the word "event" is already heavily overloaded (PDUs, EDUs, account data, ...) and we don't need to make that worse.
Secondly, "fact" emphasises that the things we append to a stream cannot change after the fact.

[^2]: A fact might be expressed with 0 rows, e.g. if we opened a transaction to persist an event, but failed and rolled the transaction back before marking the fact as completed.
In principle a fact might be expressed with 2 or more rows; if so, each of those rows should share the fact's stream ID.

[^3]: This communication used to happen directly with the writers [over TCP](../../tcp_replication.md);
nowadays it's done via Redis's Pubsub.
