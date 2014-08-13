Directory Structure
===================

Warning: this may be a bit stale...

::

    .
    ├── cmdclient           Basic CLI python Matrix client
    ├── demo                Scripts for running standalone Matrix demos
    ├── docs                All doc, including the draft Matrix API spec
    │   ├── client-server       The client-server Matrix API spec
    │   ├── model               Domain-specific elements of the Matrix API spec
    │   ├── server-server       The server-server model of the Matrix API spec
    │   └── sphinx              The internal API doc of the Synapse homeserver
    ├── experiments         Early experiments of using Synapse's internal APIs
    ├── graph               Visualisation of Matrix's distributed message store 
    ├── synapse             The reference Matrix homeserver implementation
    │   ├── api                 Common building blocks for the APIs
    │   │   ├── events              Definition of state representation Events 
    │   │   └── streams             Definition of streamable Event objects
    │   ├── app                 The __main__ entry point for the homeserver
    │   ├── crypto              The PKI client/server used for secure federation
    │   │   └── resource            PKI helper objects (e.g. keys)
    │   ├── federation          Server-server state replication logic
    │   ├── handlers            The main business logic of the homeserver
    │   ├── http                Wrappers around Twisted's HTTP server & client
    │   ├── rest                Servlet-style RESTful API
    │   ├── storage             Persistence subsystem (currently only sqlite3)
    │   │   └── schema              sqlite persistence schema
    │   └── util                Synapse-specific utilities
    ├── tests               Unit tests for the Synapse homeserver
    └── webclient           Basic AngularJS Matrix web client


