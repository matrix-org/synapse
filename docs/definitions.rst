Definitions
===========

# *Event* -- A JSON object that represents a piece of information to be
distributed to the the room. The object includes a payload and metadata,
including a `type` used to indicate what the payload is for and how to process
them. It also includes one or more references to previous events.

# *Event graph* -- Events and their references to previous events form a
directed acyclic graph. All events must be a descendant of the first event in a
room, except for a few special circumstances.

# *State event* -- A state event is an event that has a non-null string valued
`state_key` field. It may also include a `prev_state` key referencing exactly
one state event with the same type and state key, in the same event graph.

# *State tree* -- A state tree is a tree formed by a collection of state events
that have the same type and state key (all in the same event graph.

# *State resolution algorithm* -- An algorithm that takes a state tree as input
and selects a single leaf node.

# *Current state event* -- The leaf node of a given state tree that has been
selected by the state resolution algorithm.

# *Room state* / *state dictionary* / *current state* -- A mapping of the pair
(event type, state key) to the current state event for that pair.

# *Room* -- An event graph and its associated state dictionary. An event is in
the room if it is part of the event graph.

# *Topological ordering* -- The partial ordering that can be extracted from the
event graph due to it being a DAG.

(The state definitions are purposely slightly ill-defined, since if we allow
deleting events we might end up with multiple state trees for a given event
type and state key pair.)

Federation specific
-------------------
# *(Persistent data unit) PDU* -- An encoding of an event for distribution of
the server to server protocol.

# *(Ephemeral data unit) EDU* -- A piece of information that is sent between
servers and doesn't encode an event.

Client specific
---------------
# *Child events* -- Events that reference a single event in the same room
independently of the event graph.

# *Collapsed events* -- Events that have all child events that reference it
included in the JSON object.
