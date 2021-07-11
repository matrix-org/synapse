Purge history API examples
==========================

# `purge_history.sh`

A bash file, that uses the
[purge history API](https://matrix-org.github.io/synapse/latest/admin_api/purge_history_api.html)
to purge all messages in a list of rooms up to a certain event. You can select a 
timeframe or a number of messages that you want to keep in the room.

Just configure the variables DOMAIN, ADMIN, ROOMS_ARRAY and TIME at the top of
the script.

# `purge_remote_media.sh`

A bash file, that uses the
[purge history API](https://matrix-org.github.io/synapse/latest/admin_api/purge_history_api.html)
to purge all old cached remote media.
