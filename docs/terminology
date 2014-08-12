===========
Terminology
===========

A list of definitions of specific terminology used among these documents.
These terms were originally taken from the server-server documentation, and may
not currently match the exact meanings used in other places; though as a
medium-term goal we should encourage the unification of this terminology.


Terms
=====

Context:
  A single human-level entity of interest (currently, a chat room)

EDU (Ephemeral Data Unit):
  A message that relates directly to a given pair of home servers that are
  exchanging it. EDUs are short-lived messages that related only to one single
  pair of servers; they are not persisted for a long time and are not forwarded
  on to other servers. Because of this, they have no internal ID nor previous
  EDUs reference chain.

Event:
  A record of activity that records a single thing that happened on to a context
  (currently, a chat room). These are the "chat messages" that Synapse makes
  available.
  [[NOTE(paul): The current server-server implementation calls these simply
  "messages" but the term is too ambiguous here; I've called them Events]]

Pagination:
  The process of synchronising historic state from one home server to another,
  to backfill the event storage so that scrollback can be presented to the
  client(s).

PDU (Persistent Data Unit):
  A message that relates to a single context, irrespective of the server that
  is communicating it. PDUs either encode a single Event, or a single State
  change. A PDU is referred to by its PDU ID; the pair of its origin server
  and local reference from that server.

PDU ID:
  The pair of PDU Origin and PDU Reference, that together globally uniquely
  refers to a specific PDU.

PDU Origin:
  The name of the origin server that generated a given PDU. This may not be the
  server from which it has been received, due to the way they are copied around
  from server to server. The origin always records the original server that
  created it.

PDU Reference:
  A local ID used to refer to a specific PDU from a given origin server. These
  references are opaque at the protocol level, but may optionally have some
  structured meaning within a given origin server or implementation.

Presence:
  The concept of whether a user is currently online, how available they declare
  they are, and so on. See also: doc/model/presence

Profile:
  A set of metadata about a user, such as a display name, provided for the
  benefit of other users. See also: doc/model/profiles

Room ID:
  An opaque string (of as-yet undecided format) that identifies a particular
  room and used in PDUs referring to it.

Room Alias:
  A human-readable string of the form #name:some.domain that users can use as a
  pointer to identify a room; a Directory Server will map this to its Room ID

State:
  A set of metadata maintained about a Context, which is replicated among the
  servers in addition to the history of Events.

User ID:
  A string of the form @localpart:domain.name that identifies a user for
  wire-protocol purposes. The localpart is meaningless outside of a particular
  home server. This takes a human-readable form that end-users can use directly
  if they so wish, avoiding the 3PIDs.

Transaction:
  A message which relates to the communication between a given pair of servers.
  A transaction contains possibly-empty lists of PDUs and EDUs.

