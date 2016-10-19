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

/*
 * Update any email addresses that were stored with mixed case into all
 * lowercase
 */
UPDATE user_threepids SET address = LOWER(address) where medium = 'email';

/* Add an index for the select we do on passwored reset */
CREATE INDEX user_threepids_medium_address on user_threepids (medium, address);
