Media Repository 
================

*Synapse implementation-specific details for the media repository*

The media repository is where attachments and avatar photos are stored.
It stores attachment content and thumbnails for media uploaded by local users.
It caches attachment content and thumbnails for media uploaded by remote users.

Storage
-------

Each item of media is assigned a ``media_id`` when it is uploaded.
The ``media_id`` is a randomly chosen, URL safe 24 character string.
Metadata such as the MIME type, upload time and length are stored in the
sqlite3 database indexed by ``media_id``.
Content is stored on the filesystem under a ``"local_content"`` directory.
Thumbnails are stored under a ``"local_thumbnails"`` directory.
The item with ``media_id`` ``"aabbccccccccdddddddddddd"`` is stored under
``"local_content/aa/bb/ccccccccdddddddddddd"``. Its thumbnail with width
``128`` and height ``96`` and type ``"image/jpeg"`` is stored under
``"local_thumbnails/aa/bb/ccccccccdddddddddddd/128-96-image-jpeg"``
Remote content is cached under ``"remote_content"`` directory. Each item of
remote content is assigned a local "``filesystem_id``" to ensure that the
directory structure ``"remote_content/server_name/aa/bb/ccccccccdddddddddddd"``
is appropriate. Thumbnails for remote content are stored under
``"remote_thumbnails/server_name/..."``
