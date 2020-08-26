Purge Remote Media API
======================

The purge remote media API allows server admins to purge old cached remote
media.

The API is::

    POST /_synapse/admin/v1/purge_media_cache?before_ts=<unix_timestamp_in_ms>

    {}

\... which will remove all cached media that was last accessed before
``<unix_timestamp_in_ms>``.

To use it, you will need to authenticate by providing an ``access_token`` for a
server admin: see `README.rst <README.rst>`_.

If the user re-requests purged remote media, synapse will re-request the media
from the originating server.
