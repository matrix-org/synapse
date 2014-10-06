State Resolution
================
This section describes why we need state resolution and how it works.


Motivation
-----------
We want to be able to associate some shared state with rooms, e.g. a room name
or members list. This is done by having a current state dictionary that maps
from the pair event type and state key to an event.

However, since the servers involved in the room are distributed we need to be
able to handle the case when two (or more) servers try and update the state at
the same time. This is done via the state resolution algorithm.


State Tree
------------
State events contain a reference to the state it is trying to replace. These
relations form a tree where the current state is one of the leaf nodes.

Note that state events are events, and so are part of the PDU graph. Thus we
can be sure that (modulo the internet being particularly broken) we will see
all state events eventually.


Algorithm requirements
----------------------
We want the algorithm to have the following properties:
- Since we aren't guaranteed what order we receive state events in, except that
  we see parents before children, the state resolution algorithm must not depend
  on the order and must always come to the same result. 
- If we receive a state event whose parent is the current state, then the
  algorithm will select it.
- The algorithm does not depend on internal state, ensuring all servers should
  come to the same decision.

These three properties mean it is enough to keep track of the current state and
compare it with any new proposed state, rather than having to keep track of all
the leafs of the tree and recomputing across the entire state tree.


Current Implementation
----------------------
The current implementation works as follows: Upon receipt of a newly proposed
state change we first find the common ancestor. Then we take the maximum
across each branch of the users' power levels, if one is higher then it is
selected as the current state. Otherwise, we check if one chain is longer than
the other, if so we choose that one. If that also fails, then we concatenate
all the pdu ids and take a SHA1 hash and compare them to select a common
ancestor.
