/* Copyright 2016 OpenMarket Ltd
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

CREATE TABLE local_media_repository_thumbnails2 ( media_id TEXT, thumbnail_width INTEGER, thumbnail_height INTEGER, thumbnail_type TEXT, thumbnail_method TEXT, thumbnail_length INTEGER, UNIQUE ( media_id, thumbnail_width, thumbnail_height, thumbnail_type, thumbnail_method ) );
INSERT INTO local_media_repository_thumbnails2 SELECT * FROM local_media_repository_thumbnails;
DROP TABLE local_media_repository_thumbnails;
ALTER TABLE local_media_repository_thumbnails2 RENAME TO local_media_repository_thumbnails;
CREATE INDEX local_media_repository_thumbnails_media_id ON local_media_repository_thumbnails (media_id);

CREATE TABLE remote_media_cache_thumbnails2 ( media_origin TEXT, media_id TEXT, thumbnail_width INTEGER, thumbnail_height INTEGER, thumbnail_method TEXT, thumbnail_type TEXT, thumbnail_length INTEGER, filesystem_id TEXT, UNIQUE ( media_origin, media_id, thumbnail_width, thumbnail_height, thumbnail_type, thumbnail_method ) );
INSERT INTO remote_media_cache_thumbnails2 SELECT * FROM remote_media_cache_thumbnails;
DROP TABLE remote_media_cache_thumbnails;
ALTER TABLE remote_media_cache_thumbnails2 RENAME TO remote_media_cache_thumbnails;
