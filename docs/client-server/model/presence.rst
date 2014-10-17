API Efficiency
==============

A simple implementation of presence messaging has the ability to cause a large
amount of Internet traffic relating to presence updates. In order to minimise
the impact of such a feature, the following observations can be made:

 * There is no point in a Home Server polling status for peers in a user's
   presence list if the user has no clients connected that care about it.

 * It is highly likely that most presence subscriptions will be symmetric - a
   given user watching another is likely to in turn be watched by that user.

 * It is likely that most subscription pairings will be between users who share
   at least one Room in common, and so their Home Servers are actively
   exchanging message PDUs or transactions relating to that Room.

 * Presence update messages do not need realtime guarantees. It is acceptable to
   delay delivery of updates for some small amount of time (10 seconds to a
   minute).

The general model of presence information is that of a HS registering its
interest in receiving presence status updates from other HSes, which then
promise to send them when required. Rather than actively polling for the
currentt state all the time, HSes can rely on their relative stability to only
push updates when required.

A Home Server should not rely on the longterm validity of this presence
information, however, as this would not cover such cases as a user's server
crashing and thus failing to inform their peers that users it used to host are
no longer available online. Therefore, each promise of future updates should
carry with a timeout value (whether explicit in the message, or implicit as some
defined default in the protocol), after which the receiving HS should consider
the information potentially stale and request it again.

However, because of the likelyhood that two home servers are exchanging messages
relating to chat traffic in a room common to both of them, the ongoing receipt
of these messages can be taken by each server as an implicit notification that
the sending server is still up and running, and therefore that no status changes
have happened; because if they had the server would have sent them. A second,
larger timeout should be applied to this implicit inference however, to protect
against implementation bugs or other reasons that the presence state cache may
become invalid; eventually the HS should re-enquire the current state of users
and update them with its own.

The following workflows can therefore be used to handle presence updates:

 1 When a user first appears online their HS sends a message to each other HS
   containing at least one user to be watched; each message carrying both a
   notification of the sender's new online status, and a request to obtain and
   watch the target users' presence information. This message implicitly
   promises the sending HS will now push updates to the target HSes.

 2 The target HSes then respond a single message each, containing the current
   status of the requested user(s). These messages too implicitly promise the
   target HSes will themselves push updates to the sending HS.

   As these messages arrive at the sending user's HS they can be pushed to the
   user's client(s), possibly batched again to ensure not too many small
   messages which add extra protocol overheads.

At this point, all the user's clients now have the current presence status
information for this moment in time, and have promised to send each other
updates in future.

 3 The HS maintains two watchdog timers per peer HS it is exchanging presence
   information with. The first timer should have a relatively small expiry
   (perhaps 1 minute), and the second timer should have a much longer time
   (perhaps 1 hour).

 4 Any time any kind of message is received from a peer HS, the short-term
   presence timer associated with it is reset.

 5 Whenever either of these timers expires, an HS should push a status reminder
   to the target HS whose timer has now expired, and request again from that
   server the status of the subscribed users.

 6 On receipt of one of these presence status reminders, an HS can reset both
   of its presence watchdog timers.

To avoid bursts of traffic, implementations should attempt to stagger the expiry
of the longer-term watchdog timers for different peer HSes.

When individual users actively change their status (either by explicit requests
from clients, or inferred changes due to idle timers or client timeouts), the HS
should batch up any status changes for some reasonable amount of time (10
seconds to a minute). This allows for reduced protocol overheads in the case of
multiple messages needing to be sent to the same peer HS; as is the likely
scenario in many cases, such as a given human user having multiple user
accounts.


API Requirements
================

The data model presented here puts the following requirements on the APIs:

Client-Server
-------------

Requests that a client can make to its Home Server

 * get/set current presence state
   Basic enumeration + ability to set a custom piece of text

 * report per-device idle time
   After some (configurable?) idle time the device should send a single message
   to set the idle duration. The HS can then infer a "start of idle" instant and
   use that to keep the device idleness up to date. At some later point the
   device can cancel this idleness.

 * report per-device type
   Inform the server that this device is a "mobile" device, or perhaps some
   other to-be-defined category of reduced capability that could be presented to
   other users.

 * start/stop presence polling for my presence list
   It is likely that these messages could be implicitly inferred by other
   messages, though having explicit control is always useful.

 * get my presence list
   [implicit poll start?]
   It is possible that the HS doesn't yet have current presence information when
   the client requests this. There should be a "don't know" type too.

 * add/remove a user to my presence list

Server-Server
-------------

Requests that Home Servers make to others

 * request permission to add a user to presence list

 * allow/deny a request to add to a presence list

 * perform a combined presence state push and subscription request
   For each sending user ID, the message contains their new status.
   For each receiving user ID, the message should contain an indication on
   whether the sending server is also interested in receiving status from that
   user; either as an immediate update response now, or as a promise to send
   future updates.

Server to Client
----------------

[[TODO(paul): There also needs to be some way for a user's HS to push status
updates of the presence list to clients, but the general server-client event
model currently lacks a space to do that.]]
