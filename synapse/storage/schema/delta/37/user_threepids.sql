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
         -- We select all the addresses that are linked to the user_id that is NOT
         -- the most recently created.
         SELECT u.address
         FROM
             user_threepids AS u,
             -- `duplicate_addresses` is a table of all the email addresses that
             -- appear multiple times and when the binding was created
             (
                 SELECT lower(u1.address) AS address, max(u1.added_at) AS max_ts
                 FROM user_threepids AS u1
                 INNER JOIN user_threepids AS u2 ON u1.medium = u2.medium AND lower(u1.address) = lower(u2.address) AND u1.address != u2.address
                 WHERE u1.medium = 'email' AND u2.medium = 'email'
                 GROUP BY lower(u1.address)
             ) AS duplicate_addresses
         WHERE
             lower(u.address) = duplicate_addresses.address
             AND u.added_at != max_ts  -- NOT the most recently created
     );


-- This update is now safe since we've removed the duplicate addresses.
UPDATE user_threepids SET address = LOWER(address) WHERE medium = 'email';


/* Add an index for the select we do on passwored reset */
CREATE INDEX user_threepids_medium_address on user_threepids (medium, address);
