# How do faster joins work?

This is a work-in-progress set of notes with two goals:
- act as a reference, explaining how Synapse implements faster joins; and
- record the rationale behind our choices.

See also [MSC3902](https://github.com/matrix-org/matrix-spec-proposals/pull/3902).

The key idea is described by [MSC3706](https://github.com/matrix-org/matrix-spec-proposals/pull/3706). This allows servers to
request a lightweight response to the federation `/send_join` endpoint.
This is called a **faster join**, also known as a **partial join**. In these
notes we'll usually use the word "partial" as it matches the database schema.

## Overview: processing events in a partially-joined room

The response to a partial join consists of
- the requested join event `J`,
- a list of the servers in the room (according to the state before `J`),
- a subset of the state of the room before `J`,
- the full auth chain of that state subset.

Synapse marks the room as partially joined by adding a row to the database table
`partial_state_rooms`. It also marks the join event `J` as "partially stated",
meaning that we have neither received nor computed the full state before/after
`J`. This is done by adding a row to `partial_state_events`.

<details><summary>DB schema</summary>

```
matrix=> \d partial_state_events
Table "matrix.partial_state_events"
  Column  │ Type │ Collation │ Nullable │ Default
══════════╪══════╪═══════════╪══════════╪═════════
 room_id  │ text │           │ not null │
 event_id │ text │           │ not null │
 
matrix=> \d partial_state_rooms
                Table "matrix.partial_state_rooms"
         Column         │  Type  │ Collation │ Nullable │ Default 
════════════════════════╪════════╪═══════════╪══════════╪═════════
 room_id                │ text   │           │ not null │ 
 device_lists_stream_id │ bigint │           │ not null │ 0
 join_event_id          │ text   │           │          │ 
 joined_via             │ text   │           │          │ 

matrix=> \d partial_state_rooms_servers
     Table "matrix.partial_state_rooms_servers"
   Column    │ Type │ Collation │ Nullable │ Default 
═════════════╪══════╪═══════════╪══════════╪═════════
 room_id     │ text │           │ not null │ 
 server_name │ text │           │ not null │ 
```

Indices, foreign-keys and check constraints are omitted for brevity.
</details>

While partially joined to a room, Synapse receives events `E` from remote
homeservers as normal, and can create events at the request of its local users.
However, we run into trouble when we enforce the [checks on an event].

> 1. Is a valid event, otherwise it is dropped. For an event to be valid, it
     must contain a room_id, and it must comply with the event format of that
>    room version.
> 2. Passes signature checks, otherwise it is dropped.
> 3. Passes hash checks, otherwise it is redacted before being processed further.
> 4. Passes authorization rules based on the event’s auth events, otherwise it
>    is rejected.
> 5. **Passes authorization rules based on the state before the event, otherwise
>    it is rejected.**
> 6. **Passes authorization rules based on the current state of the room,
>    otherwise it is “soft failed”.**

[checks on an event]: https://spec.matrix.org/v1.5/server-server-api/#checks-performed-on-receipt-of-a-pdu

We can enforce checks 1--4 without any problems.
But we cannot enforce checks 5 or 6 with complete certainty, since Synapse does
not know the full state before `E`, nor that of the room.

### Partial state

Instead, we make a best-effort approximation.
While the room is considered partially joined, Synapse tracks the "partial
state" before events.
This works in a similar way as regular state:

- The partial state before `J` is that given to us by the partial join response.
- The partial state before an event `E` is the resolution of the partial states
  after each of `E`'s `prev_event`s.
- If `E` is rejected or a message event, the partial state after `E` is the
  partial state before `E`.
- Otherwise, the partial state after `E` is the partial state before `E`, plus
  `E` itself.

More concisely, partial state propagates just like full state; the only
difference is that we "seed" it with an incomplete initial state.
Synapse records that we have only calculated partial state for this event with
a row in `partial_state_events`.

While the room remains partially stated, check 5 on incoming events to that
room becomes:

> 5. Passes authorization rules based on **the resolution between the partial
>    state before `E` and `E`'s auth events.** If the event fails to pass
>    authorization rules, it is rejected.

Additionally, check 6 is deleted: no soft-failures are enforced.

While partially joined, the current partial state of the room is defined as the
resolution across the partial states after all forward extremities in the room.

_Remark._ Events with partial state are _not_ considered
[outliers](../room-dag-concepts.md#outliers).

### Approximation error

Using partial state means the auth checks can fail in a few different ways[^2].

[^2]: Is this exhaustive?

- We may erroneously accept an incoming event in check 5 based on partial state
  when it would have been rejected based on full state, or vice versa.
- This means that an event could erroneously be added to the current partial
  state of the room when it would not be present in the full state of the room,
  or vice versa.
- Additionally, we may have skipped soft-failing an event that would have been
  soft-failed based on full state.

(Note that the discrepancies described in the last two bullets are user-visible.)

This means that we have to be very careful when we want to lookup pieces of room
state in a partially-joined room. Our approximation of the state may be
incorrect or missing. But we can make some educated guesses. If

- our partial state is likely to be correct, or
- the consequences of our partial state being incorrect are minor,

then we proceed as normal, and let the resync process fix up any mistakes (see
below).

When is our partial state likely to be correct?

- It's more accurate the closer we are to the partial join event. (So we should
  ideally complete the resync as soon as possible.)
- Non-member events: we will have received them as part of the partial join
  response, if they were part of the room state at that point. We may
  incorrectly accept or reject updates to that state (at first because we lack
  remote membership information; later because of compounding errors), so these
  can become incorrect over time.
- Local members' memberships: we are the only ones who can create join and
  knock events for our users. We can't be completely confident in the
  correctness of bans, invites and kicks from other homeservers, but the resync
  process should correct any mistakes.
- Remote members' memberships: we did not receive these in the /send_join
  response, so we have essentially no idea if these are correct or not.

In short, we deem it acceptable to trust the partial state for non-membership
and local membership events. For remote membership events, we wait for the
resync to complete, at which point we have the full state of the room and can
proceed as normal.

### Fixing the approximation with a resync

The partial-state approximation is only a temporary affair. In the background,
synapse beings a "resync" process. This is a continuous loop, starting at the
partial join event and proceeding downwards through the event graph. For each 
`E` seen in the room since partial join, Synapse will fetch 

- the event ids in the state of the room before `E`, via 
  [`/state_ids`](https://spec.matrix.org/v1.5/server-server-api/#get_matrixfederationv1state_idsroomid);
- the event ids in the full auth chain of `E`, included in the `/state_ids` 
  response; and
- any events from the previous two bullets that Synapse hasn't persisted, via
  [`/state](https://spec.matrix.org/v1.5/server-server-api/#get_matrixfederationv1stateroomid).

This means Synapse has (or can compute) the full state before `E`, which allows
Synapse to properly authorise or reject `E`. At this point ,the event
is considered to have "full state" rather than "partial state". We record this
by removing `E` from the `partial_state_events` table.

\[**TODO:** Does Synapse persist a new state group for the full state
before `E`, or do we alter the (partial-)state group in-place? Are state groups
ever marked as partially-stated? \]

This scheme means it is possible for us to have accepted and sent an event to 
clients, only to reject it during the resync. From a client's perspective, the 
effect is similar to a retroactive 
state change due to state resolution---i.e. a "state reset".[^3]

[^3]: Clients should refresh caches to detect such a change. Rumour has it that 
sliding sync will fix this.

When all events since the join `J` have been fully-stated, the room resync
process is complete. We record this by removing the room from
`partial_state_rooms`.

## Faster joins on workers

For the time being, the resync process happens on the master worker.
A new replication stream `un_partial_stated_room` is added. Whenever a resync
completes and a partial-state room becomes fully stated, a new message is sent
into that stream containing the room ID.

## Notes on specific cases

> **NB.** The notes below are rough. Some of them are hidden under `<details>`
disclosures because they have yet to be implemented in mainline Synapse.

### Creating events during a partial join

When sending out messages during a partial join, we assume our partial state is 
accurate and proceed as normal. For this to have any hope of succeeding at all,
our partial state must contain an entry for each of the (type, state key) pairs
[specified by the auth rules](https://spec.matrix.org/v1.3/rooms/v10/#authorization-rules):

- `m.room.create`
- `m.room.join_rules`
- `m.room.power_levels`
- `m.room.third_party_invite`
- `m.room.member`

The first four of these should be present in the state before `J` that is given
to us in the partial join response; only membership events are omitted. In order
for us to consider the user joined, we must have their membership event. That
means the only possible omission is the target's membership in an invite, kick
or ban.

The worst possibility is that we locally invite someone who is banned according to
the full state, because we lack their ban in our current partial state. The rest 
of the federation---at least, those who are fully joined---should correctly 
enforce the [membership transition constraints](
    https://spec.matrix.org/v1.3/client-server-api/#room-membership
). So any the erroneous invite should be ignored by fully-joined
homeservers and resolved by the resync for partially-joined homeservers.



In more generality, there are two problems we're worrying about here:

- We might create an event that is valid under our partial state, only to later
  find out that is actually invalid according to the full state.
- Or: we might refuse to create an event that is invalid under our partial
  state, even though it would be perfectly valid under the full state.

However we expect such problems to be unlikely in practise, because

- We trust that the room has sensible power levels, e.g. that bad actors with
  high power levels are demoted before their ban.
- We trust that the resident server provides us up-to-date power levels, join
  rules, etc.
- State changes in rooms are relatively infrequent, and the resync period is
  relatively quick.

#### Sending out the event over federation

**TODO:** needs prose fleshing out.

Normally: send out in a fed txn to all HSes in the room.
We only know that some HSes were in the room at some point. Wat do.
Send it out to the list of servers from the first join.
**TODO** what do we do here if we have full state?
If the prev event was created by us, we can risk sending it to the wrong HS. (Motivation: privacy concern of the content. Not such a big deal for a public room or an encrypted room. But non-encrypted invite-only...)
But don't want to send out sensitive data in other HS's events in this way.

Suppose we discover after resync that we shouldn't have sent out one our events (not a prev_event) to a target HS. Not much we can do.
What about if we didn't send them an event but shouldn't've?
E.g. what if someone joined from a new HS shortly after you did? We wouldn't talk to them.
Could imagine sending out the "Missed" events after the resync but... painful to work out what they should have seen if they joined/left.
Instead, just send them the latest event (if they're still in the room after resync) and let them backfill.(?)
- Don't do this currently.
- If anyone who has received our messages sends a message to a HS we missed, they can backfill our messages
- Gap: rooms which are infrequently used and take a long time to resync.

### Joining after a partial join

**NB.** Not yet implemented.

<details>

**TODO:** needs prose fleshing out. Liase with Matthieu. Explain why /send_join
(Rich was surprised we didn't just create it locally. Answer: to try and avoid
a join which then gets rejected after resync.)

We don't know for sure that any join we create would be accepted.
E.g. the joined user might have been banned; the join rules might have changed in a way that we didn't realise... some way in which the partial state was mistaken.
Instead, do another partial make-join/send-join handshake to confirm that the join works.
- Probably going to get a bunch of duplicate state events and auth events.... but the point of partial joins is that these should be small. Many are already persisted = good.
- What if the second send_join response includes a different list of reisdent HSes? Could ignore it.
  - Could even have a special flag that says "just make me a join", i.e. don't bother giving me state or servers in room. Deffo want the auth chain tho.
- SQ: wrt device lists it's a lot safer to ignore it!!!!!
- What if the state at the second join is inconsistent with what we have? Ignore it?

</details>

### Leaving (and kicks and bans) after a partial join

**NB.** Not yet implemented.

<details>

When you're fully joined to a room, to have `U` leave a room their homeserver
needs to

- create a new leave event for `U` which will be accepted by other homeservers,
  and
- send that event `U` out to the homeservers in the federation.

When is a leave event accepted? See
[v10 auth rules](https://spec.matrix.org/v1.5/rooms/v10/#authorization-rules):

> 4. If type is m.room.member: [...]
     >
     >    5. If membership is leave:
             >
             >       1. If the sender matches state_key, allow if and only if that user’s current membership state is invite, join, or knock.
>       2. [...]

I think this means that (well-formed!) self-leaves are governed entirely by
4.5.1. This means that if we correctly calculate state which says that `U` is
invited, joined or knocked and include it in the leave's auth events, our event
is accepted by checks 4 and 5 on incoming events.

> 4. Passes authorization rules based on the event’s auth events, otherwise
     >    it is rejected.
> 5. Passes authorization rules based on the state before the event, otherwise
     >    it is rejected.

The only way to fail check 6 is if the receiving server's current state of the
room says that `U` is banned, has left, or has no membership event. But this is
fine: the receiving server already thinks that `U` isn't in the room.

> 6. Passes authorization rules based on the current state of the room,
     >    otherwise it is “soft failed”.

For the second point (publishing the leave event), the best thing we can do is
to is publish to all HSes we know to be currently in the room. If they miss that
event, they might send us traffic in the room that we don't care about. This is
a problem with leaving after a "full" join; we don't seek to fix this with
partial joins.

(With that said: there's nothing machine-readable in the /send response. I don't
think we can deduce "destination has left the room" from a failure to /send an
event into that room?)

#### Can we still do this during a partial join?

We can create leave events and can choose what gets included in our auth events,
so we can be sure that we pass check 4 on incoming events. For check 5, we might
have an incorrect view of the state before an event.
The only way we might erroneously think a leave is valid is if

- the partial state before the leave has `U` joined, invited or knocked, but
- the full state before the leave has `U` banned, left or not present,

in which case the leave doesn't make anything worse: other HSes already consider
us as not in the room, and will continue to do so after seeing the leave.

The remaining obstacle is then: can we safely broadcast the leave event? We may
miss servers or incorrectly think that a server is in the room. Or the
destination server may be offline and miss the transaction containing our leave
event.This should self-heal when they see an event whose `prev_events` descends
from our leave.

Another option we considered was to use federation `/send_leave` to ask a
fully-joined server to send out the event on our behalf. But that introduces
complexity without much benefit. Besides, as Rich put it,

> sending out leaves is pretty best-effort currently

so this is probably good enough as-is.

#### Cleanup after the last leave

**TODO**: what cleanup is necessary? Is it all just nice-to-have to save unused
work?
</details>
