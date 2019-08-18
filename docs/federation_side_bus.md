%%%
title = "The Federation Side Bus"
abbrev = "federation-side-bus"
docName = "federation-side-bus"
ipr = "none"
workgroup = "Synapse"

[seriesInfo]
name = "RFC"
stream = "IETF"
status = "informational"
value = "federation-side-bus"

[pi]
toc = "yes"
topblock = "yes"

[[author]]
initials = "A."
surname = "Brown"
fullname = "Amber Brown"
organization = "New Vector"
    [author.address]
    email = "amberb@matrix.org"
%%%

.# Abstract

Proposal for the "Federation Side Bus" project. Proposed refactoring of federation transport code as well as externally communicating code. Proposed implementation of a message-bus style system for external communication. Proposed implementation of a prioritisation system covering different remote hosts based on liveliness as well as prioritisation of outgoing requests when experiencing backpressure.

{mainmatter}

# Introduction

On smaller machines, Synapse has problems when interacting with the federation in large rooms. Existing experience had pointed at state resolution being the performance killer, but further research with small homeservers has revealed the performance problems when communicating with many servers. The linear characteristics of having more servers in federation turns into a significant cliff in the realm of 200 or more servers on low-powered hardware, causing a "meltdown" and causing cascading failures as the server's non-responsiveness causes timeouts to clients and other servers.

## Terminology

The keywords **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL**, when they appear in this document, are to be interpreted as described in [@!RFC2119].

Additionally, the key words "**MIGHT**", "**COULD**", "**MAY WISH TO**", "**WOULD PROBABLY**", "**SHOULD CONSIDER**", and "**MUST (BUT WE KNOW YOU WON'T)**" in this document are to interpreted as described in [@!RFC6919].

The keywords **PDU**, **EDU**, and **QUERY** in this document are to be interpreted as described in the Matrix Server to Server Specification [@!s2sapi].

**EXTERNAL COMMUNICATION** is defined as outgoing communication with another logical service, such as a web server or chat bot. Communication with the configured database, the filesystem, or with workers is not included in this definition.

**FEDERATION REQUESTS** are defined as any HTTP API call in the Matrix Server-to-Server specification, including PDUs, EDUs, or queries.

**DEFERRED** can mean either the literal Twisted Deferred, or a native coroutine that can await Deferreds. Which is used in the code depends on its use of native coroutines. APIs SHOULD try and implement native coroutines where possible, but they are described as "Deferreds" for brevity.

# The Status Quo

Synapse currently performs poorly under the following situations:

- Joining a room with many servers, where the presence storm can cause Synapse to lock up and time out the room join to the client, making it seem as if joining the room "failed" when it did not
- Sending a message in a room with many servers (sending PDUs) causes CPU and RAM spikes
- Presence and typing in a room with many servers (sending EDUs) causes CPU and RAM spikes
- Viewing the user list of a large room, causing many concurrent profile fetches
- Many users doing queries about remote users

This can be attributed to the following fundamental issues:

- Synapse's use of the network is unintelligent and is not aware of resource constraints (e.g. connection limits),
- Synapse does not leverage persistent network connections and pipelining/HTTP 2.0,
- Synapse does not gracefully degrade under pressure situations, but shows total system failure.

In addition, the following issues make it more difficult to fix the above without a comprehensive approach:

- Synapse does not assign a priority to hosts, meaning that any naive rate limiting (such as the transaction queue on `atleastfornow.net`) can cause a poor user experience as misbehaving/timing out hosts can take up a slot that a well-behaved server or servers with users that are being actively communicated with could use
- Synapse does not assign a priority to requests, making a rudimentary rate limiting system difficult
- Large parts of the codebase can make external requests independently
- Synapse uses conventional HTTP clients that are poorly suited to the "message bus" style of usage that is required.

For large servers with workers, this can be mitigated somewhat by just throwing more hardware at the problem. For smaller ones, especially on constrained hardware (think ARM or shared hosting), this lack of rate limiting can cause hard spinning, swamping of resources, and total system failure.

## The Status Quo

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
- Appservices
- Identity services

TODO: More detail?

Furthermore, profiles and room directory use the general query API.

# Proposing The Federation Side Bus

The Federation Side Bus project remodels how Synapse approaches external communication. It draws naming parallels with the system bus design of personal computers and servers from the 1990s and 2000s, where the Front Side Bus was used to describe the communication interface between the CPU and its I/O systems (where the "back side bus" was instead between CPUs).

The core of the proposal is the definition of the "southbridge" (named for the I/O controller hub on a computer's FSB). The Southbridge is the only place where external communication is allowed to occur, and has a small but versatile interface for invoking said communication. This abstraction allows the Southbridge to be more intelligent about the use of network resources, as it can control all outbound data.

There are also additional abstractions and reworking of existing ones to make the internal logic more consistent. This is mostly focused on the reorganisation of the Federation code and the shifting of the Media Repo logic from being in REST servlets to handlers of their own. A reworking of ".well-known" resolution as well as hostname resolution in general is also proposed, with the end goal of increasing reliability and reducing the amount of code that needs to consider SRV/.well-known solving.

The Federation Side Bus will not alter Synapse's interaction with any of the Matrix standards, but will present the foundation for the future implementation of transports other than HTTP. HTTP/1.1 over TLS is targeted as the primary transport for Federation for this proposal, although HTTP/2.0 can be considered a "stretch goal" and desirable for its multiplexing and long-concurrent-connection qualities that would further reduce resource usage.

# Architecture

## The Southbridge

The Southbridge fully encapsulates all external communication (apart from DNS resolution). It consists of a number of queues, connection pools, and associated prioritisation and batching systems.

### Initial Federation Queue

Zero-length queue that routes Federation requests through to the host ranker.

### Host Ranker

Tracks the performance of outbound requests and routes new requests through the different queues based on Matrix host.

### Priority-Aware Federation Queue

A queue that enqueues events based on the Matrix host and requests a connection from the pool. When it has acquired a connection, it sends the events it has. If there is network pressure, the queue is responsible for giving up the connection based on a deadline. It is aware of federation semantics, and can intelligently collapse or discard EDUs or queries.

### The Request Queue

Holds HTTP requests and requests a connection from the connection pool to send them on. Used for general purpose queries (for example, .well-known lookups or URL previews).

### The Connection Pool

Holds open HTTP connections and is responsible for establishing new ones. Operates on a callback basis with the queues. Hands over a connection to the queue requesting it, and is told when the queue is done with it. Assigns deadlines for the queues to follow (e.g. time spent processing) to ensure fairness.

## Federation Subsystem

The Federation Subsystem sees a number of changes, mostly revolving around refactoring the existing code and formalising interfaces.

### Federation Resolver

Translates a Matrix homeserver hostname into "real" addresses that it can be contacted on. It is considered authoritive to the rest of the system.

### Externaliser

Queues a Federation request in the Message Queue after attaching the "real address" information.

### Controllers

Shifting of Federation logic into more logically separated modules, such as separating by purpose (messages, queries, presence, etc) for clarity.

## Media Subsystem

The functionality of the Media Repository REST APIs refactored into a handler.

## DNS Resolver

Resolves domain names to DNS records. Although informally implemented in Synapse, this new subsystem would centralise a lot of the functionality of the various DNS resolvers used.

# Implementation Plan

The implementation plan has three phases -- cleanup, plumbing, and optimising.

Cleanup focuses on shifting about existing code to fit the new model better. This involves implementing the Federation Resolver and cleaning up the media APIs.

Plumbing involves laying the groundwork for the changes. This involves writing a more controllable HTTP client, implementing the queueing and connection pool, and hooking it up to the existing Federation abstraction. The development of other queues and pools (like for URL previews, well-known lookups, etc) will also be done here, although can be done concurrently.

Optimising involves using these abstractions to allow Synapse to operate with network activity restrictions. This includes adding rate limiting, EDU collapsing,

## Decouple the Media APIs from the REST APIs

This should all be moved out into a handler of its own, instead of existing in the REST APIs.

## Implement the Federation Resolver

The base of the Federation Resolver can be implemented and placed in Synapse without much disruption.

Requirements:

- A ResolvedFederationAddress object which can encapsulate the results.
- Simple, one-function-call API to fetch the information about the "real host".
    - Inputs:
        - Matrix server name.
    - Outputs:
        - Hostname to verify the TLS certificate against (which might not be the Matrix server name if .well-known is in use)
        - A list of IP addresses to contact the Matrix service by. This SHOULD contain priority and weight data to allow the connection pool to connect to preferred hosts, but MAY just be ordered in rank of preference without any priority or weight information.
        - MUST be encapsulated in a ResolvedFederationAddress object.

## Implement the HTTP/1.1 Transport

Implement in the current MatrixFederationAgent and SimpleHTTPClient, with a basic connection pool.

The justification for this is that the current HTTP client libraries rely on controlling the connection itself, while we want to operate on a lower level and control the connection ourselves, and give it to the client instead. It represents an inversion of the concerns, which is why we have to provide this part ourselves.

This is not a large asking, as the h11 library implements all the logic (and is a much more solid HTTP state machine than Twisted's current HTTP Agent implementation). If it implements IAgent, we may wish to contribute this up to Twisted.

Requirements:

- A HTTP/1.1 compliant transport.
    - SHOULD utilise the h11 library.
    - MUST support HTTP/1.1 keep-alive, but MUST NOT send multiple requests at once (pipelining).
    - SHOULD implement Twisted's IAgent/IResponse interface.
    - MUST take a TCP connection as an argument. The client MUST NOT instantiate the connection itself.
- A basic connection pool.
    - MUST implement a method to request a connection from the ResolvedFederationAddress object that returns a Deferred resolving to the TCP connection.
    - MAY use the first IP listed in the ResolvedFederationAddress (matching current behaviour).
    - MUST verify the TLS matches the hostname in the ResolvedFederationAddress when the connection is made.
    - MUST return an error to the connection requests if the TLS connection fails.
    - SHOULD keep connections around until they time out, and serve them to subsequent requests if they are alive.
    - SHOULD NOT implement any form of rate limiting, as that will be implemented later.
- MatrixFederationClient MUST use this connection pool and transport in place of treq.
- MatrixFederationClient MUST query the Federation Resolver for the ResolvedFederationAddress to use.
- Users of the MatrixFederationClient MUST NOT call the FederationResolver before making the request.

Questions:

- Do we need to support HTTP/1.0?
    - I don't think it's realistically required, and is expensive. The specification lists "HTTP/1.1" specifically in the examples, but does not call out HTTP/1.1 as the minimum supported version.

## Implement the Federation Queue

Implement the Federation Queue API. This Queue is not used at this stage.

Requirements:

- FederationResponse object
    - MUST be the root interface for the purposes of typing.
    - MUST have a common "status code" attribute with the numerical code and description.
- FederationErrorResponse object
    - MUST implement FederationResponse
    - MUST have errcode and error from the JSON body as attributes, and all other keys in an 'other' mapping.
- FederationQueryResponse object
    - MUST implement FederationResponse
    - MAY have further subclasses that implement particular responses to queries.
    - MUST have the JSON response as an attribute.
- FederationTransactionResponse object
    - MUST implement FederationResponse
    - MUST have the PDU processing results as an attribute.

- OutgoingEDU object
    - MUST have edu_type and content as attributes.
    - MUST have the time that it was created.
- OutgoingPDU object
    - MUST have a content attribute which contains the PDU data.
- OutgoingQuery object
    - MUST have a template of the path.
    - MUST NOT add query or body parameters to the path.
    - MUST store the path, query, and JSON body arguments.
    - MUST implement a method that returns the fully resolved path with query arguments and the body as a dictionary, for consumption by the Queue.
    - MAY have subclasses that create more usable instantiators based on the particular query.

- The base FederationQueue
    - MUST request a connection from the ConnectionPool to send requests.
    - MUST return the connection to the Connection Pool when it has sent its requests.
    - MUST NOT send more requests than were initially in its queue when the connection was granted from the Pool.
    - MUST create a HTTP Transport for its uses. It MUST destroy it after the connection is returned.
    - MUST be able to encode JSON bodies and create requests.
    - MUST be able to create a transaction from the EDUs/PDUs in the queue when it has a connection.
    - MAY collapse EDUs based on their time of creation or "cancelling out".
    - MAY remove EDUs from the queue when under queue pressure.
    - SHOULD send PDUs and EDUs in the order they were given. Future implementations MAY prioritise certain PDUs over others (e.g. direct messages).
    - MUST remove EDUs/PDUs that have been sent in a transaction from the queue.
    - MUST remove queries that have been given a response from the queue.
    - MAY retry queries that fail with transient errors instead of delivering the real error to the querier.
    - MUST remove queries from the queue that have passed their wall-clock timeout and return a FederationErrorResponse, even if they have not been sent.
- An API to add a EDU/PDU onto the Queue.
    - MUST require a ResolvedFederationAddress.
    - MUST take a OutgoingPDU or OutgoingEDU object.
- An API to make a Federation query.
    - MUST require a ResolvedFederationAddress.
    - MUST list an acceptable timeout. This MAY be 0 to mean that the query should be retried forever.
    - MUST return a Deferred that fires with a FederationResponse.

Questions:

- Typing on interfaces -- there's a mypy zope.interface plugin?
- What to do with backpressure on down hosts? Do we discard the queue?

## Handle Transactions and Queries via the Federation Queue

Move the FederationSender code to use the Federation Queue.

Requirements:

- Externaliser
    - Takes Queries/EDUs/PDUs and queries the Federation Resolver for the real host information, and then forwards it to the queue.
- Synapse MUST instantiate the Externaliser, Federation Queue, and the Federation Connection Pool on startup.
- synapse.federation.sender.FederationSender MUST send events to the Externaliser.
- ... more words here...

## Implement the General Purpose Queue

A Queue that takes general HTTP requests and forwards them to a pool.

## Handle General Purpose External Communication Via the General Purpose Queue

Move the URL previewer, well-known lookup to use the General Purpose Queue

## Implement Queuing and Pooling for Pushers, Appservices, and Identity Servers

Questions:

- Is this really needed? Fitting with the existing abstraction is useful, even if it will never rate limit the pool, and we'll get the benefits of the smarter connection pooling

## TODO: Lay out the optimising section

{backmatter}


<reference anchor='s2sapi' target='https://matrix.org/docs/spec/server_server/latest'>
    <front>
        <title>Federation API</title>
        <author>
            <organization>Matrix.org Foundation C.I.C.</organization>
        </author>
        <date year='2019'/>
    </front>
</reference>