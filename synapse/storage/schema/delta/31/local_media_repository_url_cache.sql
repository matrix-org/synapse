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

CREATE TABLE local_media_repository_url_cache(
    url TEXT,              -- the URL being cached
    response_code INTEGER, -- the HTTP response code of this download attempt
    etag TEXT,             -- the etag header of this response
    expires INTEGER,       -- the number of ms this response was valid for
    og TEXT,               -- cache of the OG metadata of this URL as JSON
    media_id TEXT,         -- the media_id, if any, of the URL's content in the repo
    download_ts BIGINT     -- the timestamp of this download attempt
);

CREATE INDEX local_media_repository_url_cache_by_url_download_ts
    ON local_media_repository_url_cache(url, download_ts);
