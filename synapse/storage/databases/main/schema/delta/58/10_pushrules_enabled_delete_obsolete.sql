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
  Delete stuck 'enabled' bits that correspond to deleted or non-existent push rules.
  We ignore rules that are server-default rules because they are not defined
  in the `push_rules` table.
**/

DELETE FROM push_rules_enable WHERE
  rule_id NOT LIKE 'global/%/.m.rule.%'
  AND NOT EXISTS (
    SELECT 1 FROM push_rules
    WHERE push_rules.user_name = push_rules_enable.user_name
      AND push_rules.rule_id = push_rules_enable.rule_id
  );
