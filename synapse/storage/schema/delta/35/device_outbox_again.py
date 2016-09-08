# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
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

# Re-apply 34/device_outbox.sql since the schema version was bumped before it
# was added to develop.

import synapse.storage.prepare_database
import os


def run_create(cur, database_engine, *args, **kwargs):
    try:
        delta_dir = os.path.join(os.path.dirname(__file__), "..")
        synapse.storage.prepare_database.executescript(
            cur, os.path.join(delta_dir, "34", "device_outbox.sql")
        )
    except:
        pass
