## Streams

Synapse has a concept of "streams", which are roughly described in [`id_generators.py`](
    https://github.com/matrix-org/synapse/blob/develop/synapse/storage/util/id_generators.py
).
It is important to understand this, so let's describe them formally.
We paraphrase from the docstring of [`AbstractStreamIdGenerator`](
    https://github.com/matrix-org/synapse/blob/a719b703d9bd0dade2565ddcad0e2f3a7a9d4c37/synapse/storage/util/id_generators.py#L96
).

A stream is an append-only log `T1, T2, ..., Tn, ...` of facts which grows over time.
Only "writers" can add facts to a stream, and there may be multiple writers.

Each fact has an ID, called its "stream ID".
Readers should only process facts in ascending stream ID order.

Roughly speaking, each stream is backed by a database table.
It should have a `stream_id` column holding stream IDs, plus additional columns
as necessary to describe the fact.
(Note that it may take multiple rows (with the same `stream_id`) to describe that fact.)
Stream IDs are globally unique (enforced by Postgres sequences).

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

We may define a per-writer notion of the "current" stream ID:

> The current stream ID _for a writer W_ is the largest stream ID such that
> all transactions added by W with equal or smaller ID have completed.

Similarly, there is a global notion of current stream ID:

> The current stream ID is the largest stream ID such that
> all facts (added by any writer) with equal or smaller ID have completed.

NB. This means that if a writer opens a transaction that never completes, the current stream ID will never advance beyond that writer's last written stream ID.

For single-writer streams, the per-writer current ID and the global current ID
are the same.
Both senses of current ID are monotonic, but they may "skip" or jump over IDs
because facts complete out of order.

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

Note that a single multi-writer stream can be viewed in both ways.
For example, the events stream is treated as multiple single-writer streams (option 1) by the sync handler, so that events are sent to clients as soon as possible.
But the background process that works through events treats them as a single linear stream.

Another useful example is the cache invalidation stream.
The facts this stream holds are instructions to "you should now invalidate these cache entries".
We only ever treat this as a multiple single-writer streams as there is no important ordering between cache invalidations.
(Invalidations are self-contained facts; and the invalidations commute/are idempotent).

### Subscribing to streams

We have described streams as a data structure, but not how to listen to them for changes.

Writers track their current position.
At startup, they can find this by querying the database (which suggests that facts need to be written to the database atomically, in a transaction).

Readers need to track the current position of every writer.
At startup, they can find this by contacting each writer with a `REPLICATE` message,
requesting that all writers reply describing their current position in their streams.
This is done with a `POSITION` message.
This communication used to happen directly with the writers [over TCP](../../tcp_replication.md);
nowadays it's done via Redis's Pubsub.

> _Aside._
> We also use Redis as an external, non-persistent key-value store.

The only thing remaining is how to persist facts and advance streams.
Writers need to track the facts currently awaiting completion.
When writing a fact has completed and no earlier fact is awaiting completion, the writer can advance its current position in that stream.
Upon doing to it emits an `RDATA` message, once for every fact between the old and the new stream ID.

Readers listen for `RDATA` messages and process them to respond to the new fact.
The `RDATA` itself is not a self-contained representation of the fact;
readers will have to query the stream tables for the full details.
Readers must also advance their record of the writer's current position for that stream.

# Summary

In a nutshell: we have an append-only log with a "buffer/scratchpad" at the end where we have to wait for the sequence to be linear and contiguous.
