# Copyright 2021 The Matrix.org Foundation C.I.C.
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
from synapse.storage.engines import Sqlite3Engine


def update_event_search_to_use_porter_stemmer(cur, database_engine):
    # Upgrade the event_search table to use the porter tokenizer
    if isinstance(database_engine, Sqlite3Engine):
        cur.execute("DROP TABLE event_search")
        cur.execute(
            """CREATE VIRTUAL TABLE event_search
                       USING fts4 (tokenize=porter, event_id, room_id, sender, key, value )"""
        )

    # TODO: we just dropped the table .. do we need to do stuff to ensure its repopulated?


def run_create(cur, database_engine, *args, **kwargs):
    update_event_search_to_use_porter_stemmer(cur, database_engine)


def run_upgrade(cur, database_engine, *args, **kwargs):
    pass
