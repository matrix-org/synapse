> **Warning**
>  These architecture notes are spectacularly old, and date back
> to when Synapse was just federation code in isolation. This should be
> merged into the main spec.

# Server to Server

## Server to Server Stack

To use the server to server stack, home servers should only need to
interact with the Messaging layer.

The server to server side of things is designed into 4 distinct layers:

1.  Messaging Layer
2.  Pdu Layer
3.  Transaction Layer
4.  Transport Layer

Where the bottom (the transport layer) is what talks to the internet via
HTTP, and the top (the messaging layer) talks to the rest of the Home
Server with a domain specific API.

1. **Messaging Layer**

    This is what the rest of the Home Server hits to send messages, join rooms,
    etc. It also allows you to register callbacks for when it get's notified by
    lower levels that e.g. a new message has been received.

    It is responsible for serializing requests to send to the data
    layer, and to parse requests received from the data layer.

2. **PDU Layer**

    This layer handles:

		- duplicate `pdu_id`'s - i.e., it makes sure we ignore them.
		- responding to requests for a given `pdu_id`
		- responding to requests for all metadata for a given context (i.e. room)
		- handling incoming backfill requests

		So it has to parse incoming messages to discover which are metadata and
    which aren't, and has to correctly clobber existing metadata where
    appropriate.

    For incoming PDUs, it has to check the PDUs it references to see
    if we have missed any. If we have go and ask someone (another
    home server) for it.

3. **Transaction Layer**

		This layer makes incoming requests idempotent. i.e., it stores
		which transaction id's we have seen and what our response were.
		If we have already seen a message with the given transaction id,
		we do not notify higher levels but simply respond with the
		previous response.

		`transaction_id` is from "`GET /send/<tx_id>/`"

		It's also responsible for batching PDUs into single transaction for
		sending to remote destinations, so that we only ever have one
		transaction in flight to a given destination at any one time.

		This is also responsible for answering requests for things after a
		given set of transactions, i.e., ask for everything after 'ver' X.

4. **Transport Layer**

		This is responsible for starting a HTTP server and hitting the
		correct callbacks on the Transaction layer, as well as sending
		both data and requests for data.

## Persistence

We persist things in a single sqlite3 database. All database queries get
run on a separate, dedicated thread. This that we only ever have one
query running at a time, making it a lot easier to do things in a safe
manner.

The queries are located in the `synapse.persistence.transactions` module,
and the table information in the `synapse.persistence.tables` module.
