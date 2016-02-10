/* Copyright 2014-2016 OpenMarket Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

CREATE TABLE IF NOT EXISTS local_media_repository (
    media_id TEXT, -- The id used to refer to the media.
    media_type TEXT, -- The MIME-type of the media.
    media_length INTEGER, -- Length of the media in bytes.
    created_ts BIGINT, -- When the content was uploaded in ms.
    upload_name TEXT, -- The name the media was uploaded with.
    user_id TEXT, -- The user who uploaded the file.
    UNIQUE (media_id)
);

CREATE TABLE IF NOT EXISTS local_media_repository_thumbnails (
    media_id TEXT, -- The id used to refer to the media.
    thumbnail_width INTEGER, -- The width of the thumbnail in pixels.
    thumbnail_height INTEGER, -- The height of the thumbnail in pixels.
    thumbnail_type TEXT, -- The MIME-type of the thumbnail.
    thumbnail_method TEXT, -- The method used to make the thumbnail.
    thumbnail_length INTEGER, -- The length of the thumbnail in bytes.
    UNIQUE (
        media_id, thumbnail_width, thumbnail_height, thumbnail_type
    )
);

CREATE INDEX local_media_repository_thumbnails_media_id
    ON local_media_repository_thumbnails (media_id);

CREATE TABLE IF NOT EXISTS remote_media_cache (
    media_origin TEXT, -- The remote HS the media came from.
    media_id TEXT, -- The id used to refer to the media on that server.
    media_type TEXT, -- The MIME-type of the media.
    created_ts BIGINT, -- When the content was uploaded in ms.
    upload_name TEXT, -- The name the media was uploaded with.
    media_length INTEGER, -- Length of the media in bytes.
    filesystem_id TEXT, -- The name used to store the media on disk.
    UNIQUE (media_origin, media_id)
);

CREATE TABLE IF NOT EXISTS remote_media_cache_thumbnails (
    media_origin TEXT, -- The remote HS the media came from.
    media_id TEXT, -- The id used to refer to the media.
    thumbnail_width INTEGER, -- The width of the thumbnail in pixels.
    thumbnail_height INTEGER, -- The height of the thumbnail in pixels.
    thumbnail_method TEXT, -- The method used to make the thumbnail
    thumbnail_type TEXT, -- The MIME-type of the thumbnail.
    thumbnail_length INTEGER, -- The length of the thumbnail in bytes.
    filesystem_id TEXT, -- The name used to store the media on disk.
    UNIQUE (
        media_origin, media_id, thumbnail_width, thumbnail_height,
        thumbnail_type
     )
);

CREATE INDEX remote_media_cache_thumbnails_media_id
    ON remote_media_cache_thumbnails (media_id);
