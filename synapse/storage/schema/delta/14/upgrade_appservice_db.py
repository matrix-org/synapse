# Copyright 2015, 2016 OpenMarket Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import logging

logger = logging.getLogger(__name__)


def run_create(cur, *args, **kwargs):
    cur.execute("SELECT id, regex FROM application_services_regex")
    for row in cur.fetchall():
        try:
            logger.debug("Checking %s..." % row[0])
            json.loads(row[1])
        except ValueError:
            # row isn't in json, make it so.
            string_regex = row[1]
            new_regex = json.dumps({
                "regex": string_regex,
                "exclusive": True
            })
            cur.execute(
                "UPDATE application_services_regex SET regex=? WHERE id=?",
                (new_regex, row[0])
            )


def run_upgrade(*args, **kwargs):
    pass
