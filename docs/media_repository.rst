Media Repository
================

The media repository is where attachments and avatar photos are stored.
It stores attachment content and thumbnails for media uploaded by local users.
It caches attachment content and thumbnails for media uploaded by remote users.

Storage
-------

Each item of media is assigned a ``media_id`` when it is uploaded.
The ``media_id`` is a randomly chosen, URL safe 24 character string.
Metadata such as the MIME type, upload time and length are stored in the
sqlite3 database indexed by ``media_id``.
Content is stored on the filesystem under a "content" directory. Thumbnails are
stored under a "thumbnails" directory.
The item with ``media_id`` ``"aabbccccccccdddddddddddd"`` is stored under
``"local/content/aa/bb/ccccccccdddddddddddd"``. Its thumbnail with width
``128`` and height ``96`` and type ``"image/jpeg"`` is stored under
``"local/thumbnails/aa/bb/ccccccccdddddddddddd/128-96-image-jpeg"``
