Purge Remote Media API
======================

The purge remote media API allows server admins to purge old cached remote
media.

The API is::

    POST /_synapse/admin/v1/purge_media_cache?before_ts=<unix_timestamp_in_ms>&access_token=<access_token>

    {}

Which will remove all cached media that was last accessed before
``<unix_timestamp_in_ms>``.

If the user re-requests purged remote media, synapse will re-request the media
from the originating server.
