/* Copyright 2017 New Vector Ltd
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

-- this didn't work on SQLite 3.7 (because of lack of partial indexes), so was
-- removed and replaced with 46/local_media_repository_url_idx.sql.
--
-- CREATE INDEX local_media_repository_url_idx ON local_media_repository(created_ts) WHERE url_cache IS NOT NULL;

-- we need to change `expires` to `expires_ts` so that we can index on it. SQLite doesn't support
-- indices on expressions until 3.9.
CREATE TABLE local_media_repository_url_cache_new(
    url TEXT,
    response_code INTEGER,
    etag TEXT,
    expires_ts BIGINT,
    og TEXT,
    media_id TEXT,
    download_ts BIGINT
);

INSERT INTO local_media_repository_url_cache_new
    SELECT url, response_code, etag, expires + download_ts, og, media_id, download_ts FROM local_media_repository_url_cache;

DROP TABLE local_media_repository_url_cache;
ALTER TABLE local_media_repository_url_cache_new RENAME TO local_media_repository_url_cache;

CREATE INDEX local_media_repository_url_cache_expires_idx ON local_media_repository_url_cache(expires_ts);
CREATE INDEX local_media_repository_url_cache_by_url_download_ts ON local_media_repository_url_cache(url, download_ts);
CREATE INDEX local_media_repository_url_cache_media_idx ON local_media_repository_url_cache(media_id);
