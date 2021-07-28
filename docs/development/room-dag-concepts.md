# Room DAG concepts

## Edges

The word "edge" comes from graph theory lingo. An edge is just a connection
between two events. In Synapse, we connect events by specifying their
`prev_events`. A subsequent event points back at a previous event.

```
A (oldest) <---- B <---- C (most recent)
```


## Depth and stream ordering

Events are sorted by `(topological_ordering, stream_ordering)` where
`topological_ordering` is just `depth`. Normally, `stream_ordering` is an auto
incrementing integer but for `backfilled=true` events, it decrements.

`depth` is not re-calculated when messages are inserted into the DAG.


## Forward extremity

Most-recent-in-time events in the DAG which are not referenced by any `prev_events` yet.

The forward extremities of a room are used as the `prev_events` when the next event is sent.


## Backwards extremity

The current marker of where we have backfilled up to.

A backwards extremity is a place where the oldest-in-time events of the DAG

This is an event where we haven't fetched all of the `prev_events` for.

Once we have fetched all of it's `prev_events`, it's unmarked as backwards
extremity and those `prev_events` become the new backwards extremities.


## Outliers

We mark an event as an `outlier` when we haven't figured out the state for the
room at that point in the DAG yet.

We won't *necessarily* have the `prev_events` of an `outlier` in the database,
but it's entirely possible that we *might*. The status of whether we have all of
the `prev_events` is marked as a [backwards extremity](#backwards-extremity).

For example, when we fetch the event auth chain or state for a given event, we
mark all of those claimed auth events as outliers because we haven't done the
state calculation ourself.


### Floating outlier

A floating `outlier` is an arbitrary floating event in the DAG (as opposed to
being inline with the current DAG). This happens when it the event doesn't have
any `prev_events` or fake `prev_events` that don't exist.


## State groups

For every non-outlier event we need to know the state at that event. Instead of
storing the full state for each event in the DB (i.e. a `event_id -> state`
mapping), which is *very* space inefficient when state doesn't change, we
instead assign each different set of state a "state group" and then have
mappings of `event_id -> state_group` and `state_group -> state`.


### Stage group edges

TODO: `state_group_edges` is a further optimization...
