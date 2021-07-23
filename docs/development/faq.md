# Developer FAQ

## What is an `outlier`?

An `outlier` is an arbitrary floating event in the DAG (as opposed to being
inline with the current DAG). It also means that we don't have the state events
backfilled on the homeserver and we trust the events *claimed* auth events rather
than those we calculate and verify to be correct. 

An event can be unmarked as an `outlier` once we fetch all of its `prev_events` (you will see some `ex_outlier` code around this).


## What is a `state_group`?

For every non-outlier event we need to know the state at that event. Instead of storing the full state for each event in the DB (i.e. a `event_id -> state` mapping), which is *very* space inefficient when state doesn't change, we instead assign each different set of state a "state group" and then have mappings of `event_id -> state_group` and `state_group -> state`.


