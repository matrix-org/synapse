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

ALTER TABLE users ADD is_guest SMALLINT DEFAULT 0 NOT NULL;
/*
 * NB: any guest users created between 27 and 28 will be incorrectly
 * marked as not guests: we don't bother to fill these in correctly
 * because guest access is not really complete in 27 anyway so it's
 * very unlikley there will be any guest users created.
 */
