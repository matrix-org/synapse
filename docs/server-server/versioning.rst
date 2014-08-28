Versioning is, like, hard for backfilling backwards because of the number of Home Servers involved.

The way we solve this is by doing versioning as an acyclic directed graph of PDUs. For backfilling purposes, this is done on a per context basis. 
When we send a PDU we include all PDUs that have been received for that context that hasn't been subsequently listed in a later PDU. The trivial case is a simple list of PDUs, e.g. A <- B <- C. However, if two servers send out a PDU at the same to, both B and C would point at A - a later PDU would then list both B and C.

Problems with opaque version strings:
    - How do you do clustering without mandating that a cluster can only have one transaction in flight to a given remote home server at a time. 
      If you have multiple transactions sent at once, then you might drop one transaction, receive another with a version that is later than the dropped transaction and which point ARGH WE LOST A TRANSACTION.
    - How do you do backfilling? A version string defines a point in a stream w.r.t. a single home server, not a point in the context.

We only need to store the ends of the directed graph, we DO NOT need to do the whole one table of nodes and one of edges.
