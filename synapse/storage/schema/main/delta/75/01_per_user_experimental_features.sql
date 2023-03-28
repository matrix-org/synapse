/* Copyright 2023 The Matrix.org Foundation C.I.C
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

-- Table containing a list of experimental features and whether they are
-- enabled for a given user
CREATE TABLE per_user_experimental_features (
    -- The User ID to check/set the feature for
    user_id TEXT NOT NULL PRIMARY KEY,

    -- busy presence state enabled
    msc3026 BOOLEAN,

    -- enable unread counts
    msc2654 BOOLEAN,

    -- enable remotely toggling push notifications for another client
    msc3881 BOOLEAN,

    -- Do not require UIA when first uploading cross signing keys
    msc3967 BOOLEAN
);

