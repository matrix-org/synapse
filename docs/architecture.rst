Synapse Architecture
====================

As of the end of Oct 2014, Synapse's overall architecture looks like::

        synapse
        .-----------------------------------------------------.
        |                          Notifier                   |
        |                            ^  |                     |
        |                            |  |                     |
        |                  .------------|------.              |
        |                  | handlers/  |      |              |
        |                  |            v      |              |
        |                  | Event*Handler <--------> rest/* <=> Client
        |                  | Rooms*Handler     |              |
  HSes <=> federation/* <==> FederationHandler |              |
        |      |           | PresenceHandler   |              |
        |      |           | TypingHandler     |              |
        |      |           '-------------------'              |
        |      |                 |     |                      |
        |      |              state/*  |                      |
        |      |                 |     |                      |
        |      |                 v     v                      |
        |      `--------------> storage/*                     |
        |                          |                          |
        '--------------------------|--------------------------'
                                   v
                                .----.
                                | DB |
                                '----'

* Handlers: business logic of synapse itself.  Follows a set contract of BaseHandler:

  - BaseHandler gives us onNewRoomEvent which: (TODO: flesh this out and make it less cryptic):
 
    + handle_state(event)
    + auth(event)
    + persist_event(event)
    + notify notifier or federation(event)
   
  - PresenceHandler: use distributor to get EDUs out of Federation.  Very
    lightweight logic built on the distributor
  - TypingHandler: use distributor to get EDUs out of Federation.  Very
    lightweight logic built on the distributor
  - EventsHandler: handles the events stream...
  - FederationHandler: - gets PDU from Federation Layer; turns into an event;
    follows basehandler functionality.
  - RoomsHandler: does all the room logic, including members - lots of classes in
    RoomsHandler.
  - ProfileHandler: talks to the storage to store/retrieve profile info.

* EventFactory: generates events of particular event types.
* Notifier: Backs the events handler
* REST: Interfaces handlers and events to the outside world via HTTP/JSON.
  Converts events back and forth from JSON.
* Federation: holds the HTTP client & server to talk to other servers.  Does
  replication to make sure there's nothing missing in the graph.  Handles
  reliability.  Handles txns.
* Distributor: generic event bus. used for presence & typing only currently. 
  Notifier could be implemented using Distributor - so far we are only using for
  things which actually /require/ dynamic pluggability however as it can
  obfuscate the actual flow of control.
* Auth: helper singleton to say whether a given event is allowed to do a given
  thing  (TODO: put this on the diagram)
* State: helper singleton: does state conflict resolution. You give it an event
  and it tells you if it actually updates the state or not, and annotates the
  event up properly and handles merge conflict resolution.
* Storage: abstracts the storage engine.
