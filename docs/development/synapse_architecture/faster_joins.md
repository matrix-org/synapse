# How do faster joins work?

This is a work-in-progress set of notes with two goals:
- act as a reference, explaining how Synapse implements faster joins; and
- record the rationale behind our choices.

See also [MSC3902](https://github.com/matrix-org/matrix-spec-proposals/pull/3902).

## Overview: processing events in a partially-joined room

The response to a partial join consists of
- the requested join event `J`,
- a list of the servers in the room (according to the state before `J`),
- a subset of the state of the room before `J`,
- the full auth chain of that state subset.

Synapse marks the room as partially joined by adding a row to
`partial_state_rooms`. It also marks the join event `J` as "partially stated",
meaning that we have neither received nor computed the full state before/after
`J`. This is done by adding a row to `partial_state_events`.

[**TODO**: include a DDL definition of the partial joins tables.]

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

**TODO:** needs prose fleshing out. Needs a discussion of what happens if the
full state and partial state disagree---point out that we already have this
problem when resolution changes state but not because of a new event, requiring
clients to clear caches. Assert that sliding sync will fix this.

- /state_ids before J. Result persisted to DB?
- Continuous loop to fetch events and auth chains of any missing state events in the state before J
- Once they're all available, persist a state group(?) for the state before/after J.
- Recompute the full state of all events seen since J until there are none left.
  - (Does this use new state groups or replace old ones?)
  - (Are state groups marked as partially stated?)
- Remove events from `partial_state_events` as you go.

- Once all events have been un-partial-stated, remove the room from `partial_state_rooms`.

- Then what happens from the client-side; how are changes between partial and full state sent to clients?? Suspect not at all.

## Specific cases

### Creating events during a partial join

**TODO:** needs prose fleshing out.

Exactly the same. Pick <= 10 fwd extremities as prev events.

Can you select auth events in the current (partial) state?
- got power levels/create/join rules from the partial join.
- Will have the sender's membership: comes from a make_join handshake.
- Target's membership? E.g. kick or ban someone.
  - May not have received the target's membership in the partial join response.
  - Probably only going to kickban someone you've seen a msg from
  - If you've seen their message, they'll have cited (some previous version of) their membership...
  - Could create a reasonable looking ban event... but not a huge prioity; okay to block

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
Could imagine sending out the "Missed" events after the resync but... painful to work out what they shuld have seen if they joined/left.
Instead, just send them the latest event (if they're still in the room after resync) and let them backfill.(?)
 - Don't do this currently.
 - If anyone who has received our messages sends a message to a HS we missed, they can backfill our messages
 - Gap: rooms which are infrequently used and take a long time to resync.

### Joining after a partial join

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

### Leaving (and kicks and bans) after a partial join

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

## Faster joins on workers

**TODO**: What is Olivier's plan? :)
