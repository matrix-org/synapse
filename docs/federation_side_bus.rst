The Federation-Side Bus
=======================

As the front-side bus was the connection between the CPU and I/O, the federation-side bus will be Synapse's connection between the Homeserver and Federation I/O.

As It Stands
------------

Currently, federation traffic is sent through many different places in Synapse, without any particular queueing, rate-limiting, or priority system in place. For large servers with workers, this can be mitigated somewhat by just throwing more hardware at the problem. For smaller ones, especially on constrained hardware (think ARM or shared hosting), this lack of rate limiting can cause hard spinning, swamping of resources, and total system failure.

Currently, Synapse talks over to other servers in the following places:

- Keyring (perspectives and origin), for fetching server keys
- TransportLayerClient:
    - s.federation.federation_client
        - general federation queries
        - client key query
        - user device query
        - backfill
        - individual PDU collection
        - fetching remote room state
        - sending joins
        - sending invites
        - sending leaves
        - getting public rooms
        - querying auth chain
        - getting missing events
        - room complexity
    - s.federation.sender.transaction_manager
        - sending transactions
    - s.groups.attestations
        - fetching attestations
    - s.groups.groups_server
        - inviting and removing from group
    - s.groups.groups_client
        - fetching groups
        - fetching users from groups
- Media Repo
    - download_remote_file (linearised)

Furthermore, profiles and room directory use general queries and do not have specific functions.

The Problem With The Status Quo
-------------------------------

Synapse currently performs poorly under the following situations:

- Joining a room with many servers, where the presence storm can cause Synapse to lock up and time out the room join to the client, making it seem as if joining the room "failed" when it did not
- Sending a message in a room with many servers (sending PDUs) causes CPU and RAM spikes
- Presence and typing in a room with many servers (sending EDUs) causes CPU and RAM spikes
- Viewing the user list of a large room, causing many concurrent profile fetches (which gets rate limited by upstream servers and can cause timeouts)
- Many users doing queries about remote users

This can be attributed to the following:

- Lack of rate-limiting in many APIs
- Lack of queueing, where many requests could be arranged over less requests
- Lack of pre-flight connection
