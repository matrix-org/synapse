# Room DAG concepts

## Edges

The word "edge" comes from graph theory lingo. An edge is just a connection
between two events. In Synapse, we connect events by specifying their
`prev_events`. A subsequent event points back at a previous event.

```
A (oldest) <---- B <---- C (most recent)
```


## Depth and stream ordering

Events are normally sorted by `(topological_ordering, stream_ordering)` where
`topological_ordering` is just `depth`. In other words, we first sort by `depth`
and then tie-break based on `stream_ordering`. `depth` is incremented as new
messages are added to the DAG. Normally, `stream_ordering` is an auto
incrementing integer, but backfilled events start with `stream_ordering=-1` and decrement.

---

 - `/sync` returns things in the order they arrive at the server (`stream_ordering`).
 - `/messages` (and `/backfill` in the federation API) return them in the order determined by the event graph `(topological_ordering, stream_ordering)`.

The general idea is that, if you're following a room in real-time (i.e.
`/sync`), you probably want to see the messages as they arrive at your server,
rather than skipping any that arrived late; whereas if you're looking at a
historical section of timeline (i.e. `/messages`), you want to see the best
representation of the state of the room as others were seeing it at the time.


## Forward extremity

Most-recent-in-time events in the DAG which are not referenced by any other events' `prev_events` yet.

The forward extremities of a room are used as the `prev_events` when the next event is sent.


## Backward extremity

The current marker of where we have backfilled up to and will generally be the
`prev_events` of the oldest-in-time events we have in the DAG. This gives a starting point when
backfilling history.

When we persist a non-outlier event, we clear it as a backward extremity and set
all of its `prev_events` as the new backward extremities if they aren't already
persisted in the `events` table.


## Outliers

We mark an event as an `outlier` when we haven't figured out the state for the
room at that point in the DAG yet.

We won't *necessarily* have the `prev_events` of an `outlier` in the database,
but it's entirely possible that we *might*.

For example, when we fetch the event auth chain or state for a given event, we
mark all of those claimed auth events as outliers because we haven't done the
state calculation ourself.


## State groups

For every non-outlier event we need to know the state at that event. Instead of
storing the full state for each event in the DB (i.e. a `event_id -> state`
mapping), which is *very* space inefficient when state doesn't change, we
instead assign each different set of state a "state group" and then have
mappings of `event_id -> state_group` and `state_group -> state`.


### Stage group edges

TODO: `state_group_edges` is a further optimization...
      notes from @Azrenbeth, https://pastebin.com/seUGVGeT
