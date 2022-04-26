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

## Outliers

We mark an event as an `outlier` when we haven't figured out the state for the
room at that point in the DAG yet. They are "floating" events that we haven't
yet correlated to the DAG.

Outliers typically arise when we fetch the auth chain or state for a given
event. When that happens, we just grab the events in the state/auth chain,
without calculating the state at those events, or backfilling their
`prev_events`. Since we don't have the state at any events fetched in that
way, we mark them as outliers.

So, typically, we won't have the `prev_events` of an `outlier` in the database,
(though it's entirely possible that we *might* have them for some other
reason). Other things that make outliers different from regular events:

 * We don't have state for them, so there should be no entry in
   `event_to_state_groups` for an outlier. (In practice this isn't always
   the case, though I'm not sure why: see https://github.com/matrix-org/synapse/issues/12201).

 * We don't record entries for them in the `event_edges`,
   `event_forward_extremeties` or `event_backward_extremities` tables.

Since outliers are not tied into the DAG, they do not normally form part of the
timeline sent down to clients via `/sync` or `/messages`; however there is an
exception:

### Out-of-band membership events

A special case of outlier events are some membership events for federated rooms
that we aren't full members of. For example:

 * invites received over federation, before we join the room
 * *rejections* for said invites
 * knock events for rooms that we would like to join but have not yet joined.

In all the above cases, we don't have the state for the room, which is why they
are treated as outliers. They are a bit special though, in that they are
proactively sent to clients via `/sync`.

## Forward extremity

Most-recent-in-time events in the DAG which are not referenced by any other
events' `prev_events` yet. (In this definition, outliers, rejected events, and
soft-failed events don't count.)

The forward extremities of a room (or at least, a subset of them, if there are
more than ten) are used as the `prev_events` when the next event is sent.

The "current state" of a room (ie: the state which would be used if we
generated a new event) is, therefore, the resolution of the room states
at each of the forward extremities.

## Backward extremity

The current marker of where we have backfilled up to and will generally be the
`prev_events` of the oldest-in-time events we have in the DAG. This gives a starting point when
backfilling history.

Note that, unlike forward extremities, we typically don't have any backward
extremity events themselves in the database - or, if we do, they will be "outliers" (see
above). Either way, we don't expect to have the room state at a backward extremity.

When we persist a non-outlier event, if it was previously a backward extremity,
we clear it as a backward extremity and set all of its `prev_events` as the new
backward extremities if they aren't already persisted as non-outliers. This
therefore keeps the backward extremities up-to-date.

## State groups

For every non-outlier event we need to know the state at that event. Instead of
storing the full state for each event in the DB (i.e. a `event_id -> state`
mapping), which is *very* space inefficient when state doesn't change, we
instead assign each different set of state a "state group" and then have
mappings of `event_id -> state_group` and `state_group -> state`.


### Stage group edges

TODO: `state_group_edges` is a further optimization...
      notes from @Azrenbeth, https://pastebin.com/seUGVGeT
