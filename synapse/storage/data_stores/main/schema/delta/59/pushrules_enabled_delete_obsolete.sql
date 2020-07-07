/* Copyright 2020 The Matrix.org Foundation C.I.C.
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

/**
  Delete stuck 'enabled' bits that correspond to deleted push rules.
  We ignore rules that are server-default rules because they are not defined
  in the `push_rules` table.
**/

DELETE FROM push_rules_enable pre WHERE
  pre.rule_id NOT LIKE 'global/override/.%'
  AND pre.rule_id NOT LIKE 'global/underride/.%'
  AND pre.rule_id NOT LIKE 'global/sender/.%'
  AND pre.rule_id NOT LIKE 'global/room/.%'
  AND pre.rule_id NOT LIKE 'global/content/.%'
  AND NOT EXISTS (
    SELECT 1 FROM push_rules pr
    WHERE pr.user_name = pre.user_name
      AND pr.rule_id = pre.rule_id
  );
