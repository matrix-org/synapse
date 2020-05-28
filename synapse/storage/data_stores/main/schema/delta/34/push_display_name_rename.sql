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

DELETE FROM push_rules WHERE rule_id = 'global/override/.m.rule.contains_display_name';
UPDATE push_rules SET rule_id = 'global/override/.m.rule.contains_display_name' WHERE rule_id = 'global/underride/.m.rule.contains_display_name';

DELETE FROM push_rules_enable WHERE rule_id = 'global/override/.m.rule.contains_display_name';
UPDATE push_rules_enable SET rule_id = 'global/override/.m.rule.contains_display_name' WHERE rule_id = 'global/underride/.m.rule.contains_display_name';
