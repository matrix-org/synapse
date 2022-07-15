# Media Repository 

*Synapse implementation-specific details for the media repository*

The media repository
 * stores avatars, attachments and their thumbnails for media uploaded by local
   users.
 * caches avatars, attachments and their thumbnails for media uploaded by remote
   users.
 * caches resources and thumbnails used for URL previews.

All media in Matrix can be identified by a unique
[MXC URI](https://spec.matrix.org/latest/client-server-api/#matrix-content-mxc-uris),
consisting of a server name and media ID:
```
mxc://<server-name>/<media-id>
```

## Local Media
Synapse generates 24 character media IDs for content uploaded by local users.
These media IDs consist of upper and lowercase letters and are case-sensitive.
Other homeserver implementations may generate media IDs differently.

Local media is recorded in the `local_media_repository` table, which includes
metadata such as MIME types, upload times and file sizes.
Note that this table is shared by the URL cache, which has a different media ID
scheme.

### Paths
A file with media ID `aabbcccccccccccccccccccc` and its `128x96` `image/jpeg`
thumbnail, created by scaling, would be stored at:
```
local_content/aa/bb/cccccccccccccccccccc
local_thumbnails/aa/bb/cccccccccccccccccccc/128-96-image-jpeg-scale
```

## Remote Media
When media from a remote homeserver is requested from Synapse, it is assigned
a local `filesystem_id`, with the same format as locally-generated media IDs,
as described above.

A record of remote media is stored in the `remote_media_cache` table, which
can be used to map remote MXC URIs (server names and media IDs) to local
`filesystem_id`s.

### Paths
A file from `matrix.org` with `filesystem_id` `aabbcccccccccccccccccccc` and its
`128x96` `image/jpeg` thumbnail, created by scaling, would be stored at:
```
remote_content/matrix.org/aa/bb/cccccccccccccccccccc
remote_thumbnail/matrix.org/aa/bb/cccccccccccccccccccc/128-96-image-jpeg-scale
```
Older thumbnails may omit the thumbnailing method:
```
remote_thumbnail/matrix.org/aa/bb/cccccccccccccccccccc/128-96-image-jpeg
```

Note that `remote_thumbnail/` does not have an `s`.

## URL Previews

When generating previews for URLs, Synapse may download and cache various
resources, including images. These resources are assigned temporary media IDs
of the form `yyyy-mm-dd_aaaaaaaaaaaaaaaa`, where `yyyy-mm-dd` is the current
date and `aaaaaaaaaaaaaaaa` is a random sequence of 16 case-sensitive letters.

The metadata for these cached resources is stored in the
`local_media_repository` and `local_media_repository_url_cache` tables.

Resources for URL previews are deleted after a few days.

### Paths
The file with media ID `yyyy-mm-dd_aaaaaaaaaaaaaaaa` and its `128x96`
`image/jpeg` thumbnail, created by scaling, would be stored at:
```
url_cache/yyyy-mm-dd/aaaaaaaaaaaaaaaa
url_cache_thumbnails/yyyy-mm-dd/aaaaaaaaaaaaaaaa/128-96-image-jpeg-scale
```
