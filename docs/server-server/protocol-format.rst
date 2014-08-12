
Transaction
===========

Required keys:

============ =================== ===============================================
    Key            Type                         Description
============ =================== ===============================================
origin       String              DNS name of homeserver making this transaction.
ts           Integer             Timestamp in milliseconds on originating 
                                 homeserver when this transaction started.
previous_ids List of Strings     List of transactions that were sent immediately
                                 prior to this transaction.
pdus         List of Objects     List of updates contained in this transaction.
============ =================== ===============================================


PDU
===

Required keys:

============ ================== ================================================
    Key            Type                         Description
============ ================== ================================================
context      String             Event context identifier
origin       String             DNS name of homeserver that created this PDU.
pdu_id       String             Unique identifier for PDU within the context for
                                the originating homeserver.
ts           Integer            Timestamp in milliseconds on originating 
                                homeserver when this PDU was created.
pdu_type     String             PDU event type.
prev_pdus    List of Pairs      The originating homeserver and PDU ids of the
             of Strings         most recent PDUs the homeserver was aware of for
                                this context when it made this PDU.
depth        Integer            The maximum depth of the previous PDUs plus one.
============ ================== ================================================

Keys for state updates:

================== ============ ================================================
    Key               Type                      Description
================== ============ ================================================
is_state           Boolean      True if this PDU is updating state.
state_key          String       Optional key identifying the updated state within
                                the context.
power_level        Integer      The asserted power level of the user performing
                                the update.
min_update         Integer      The required power level needed to replace this
                                update.
prev_state_id      String       The homeserver of the update this replaces
prev_state_origin  String       The PDU id of the update this replaces.
user               String       The user updating the state.
================== ============ ================================================




