# How do State Groups work?

As a general rule, I encourage people who want to understand the deepest darkest secrets of the database schema to drop by #synapse-dev:matrix.org and ask questions.

However, one question that comes up frequently is that of how "state groups" work, and why the `state_groups_state` table gets so big, so here's an attempt to answer that question.

We need to be able to relatively quickly calculate the state of a room at any point in that room's history. In other words, we need to know the state of the room at each event in that room. This is done as follows:

A sequence of events where the state is the same are grouped together into a `state_group`; the mapping is recorded in `event_to_state_groups`. (Technically speaking, since a state event usually changes the state in the room, we are recording the state of the room *after* the given event id: which is to say, to a handwavey simplification, the first event in a state group is normally a state event, and others in the same state group are normally non-state-events.)

`state_groups` records, for each state group, the id of the room that we're looking at, and also the id of the first event in that group. (I'm not sure if that event id is used much in practice.) 

Now, if we stored all the room state for each `state_group`, that would be a huge amount of data. Instead, for each state group, we normally store the difference between the state in that group and some other state group, and only occasionally (every 100 state changes or so) record the full state.

So, most state groups have an entry in `state_group_edges` (don't ask me why it's not a column in `state_groups`) which records the previous state group in the room, and `state_groups_state` records the differences in state since that previous state group.

A full state group just records the event id for each piece of state in the room at that point.

## Known bugs with state groups

There are various reasons that we can end up creating many more state groups than we need: see https://github.com/matrix-org/synapse/issues/3364 for more details.

## Compression tool

There is a tool at https://github.com/matrix-org/rust-synapse-compress-state which can compress the `state_groups_state` on a room by-room basis (essentially, it reduces the number of "full" state groups). This can result in dramatic reductions of the storage used.