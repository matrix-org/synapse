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

 -- There may be "duplicate" emails (with different case) already in the table,
 -- so we find them and move all but the most recently used account.
 UPDATE user_threepids
 SET medium = 'email_old'
 WHERE medium = 'email'
    AND address IN (
         -- `user_last_seen` maps user_ids to the last time we saw them
         WITH user_last_seen AS (
             SELECT user_id, max(last_seen) AS ts FROM user_ips GROUP BY user_id
         ),
         -- `duplicate_addresses` is a table of all the email addresses that
         -- appear multiple times and the most recently we saw any of their users
         duplicate_addresses AS (
             SELECT lower(u1.address) AS address, max(ts.ts) AS max_ts
             FROM user_threepids AS u1
             INNER JOIN user_threepids AS u2 ON u1.medium = u2.medium AND lower(u1.address) = lower(u2.address) AND u1.address != u2.address
             INNER JOIN user_last_seen as ts ON ts.user_id = u1.user_id
             WHERE u1.medium = 'email' AND u2.medium = 'email'
             GROUP BY lower(u1.address)
         )
         -- We select all the addresses that are linked to the user_id that is NOT
         -- the most recently seen.
         SELECT u.address
         FROM
             user_threepids AS u,
             duplicate_addresses,
             user_last_seen AS ts
         WHERE
             lower(u.address) = duplicate_addresses.address
             AND u.user_id = ts.user_id
             AND ts.ts != max_ts  -- NOT the most recently used
     );


-- This update is now safe since we've removed the duplicate addresses.
UPDATE user_threepids SET address = LOWER(address) WHERE medium = 'email';


/* Add an index for the select we do on passwored reset */
CREATE INDEX user_threepids_medium_address on user_threepids (medium, address);
