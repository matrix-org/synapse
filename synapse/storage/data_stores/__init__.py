# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.
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

import logging

from synapse.storage.data_stores.main.events import PersistEventsStore
from synapse.storage.data_stores.state import StateGroupDataStore
from synapse.storage.database import Database, make_conn
from synapse.storage.engines import create_engine
from synapse.storage.prepare_database import prepare_database

logger = logging.getLogger(__name__)


class DataStores(object):
    """The various data stores.

    These are low level interfaces to physical databases.

    Attributes:
        main (DataStore)
    """

    def __init__(self, main_store_class, hs):
        # Note we pass in the main store class here as workers use a different main
        # store.

        self.databases = []
        self.main = None
        self.state = None
        self.persist_events = None

        for database_config in hs.config.database.databases:
            db_name = database_config.name
            engine = create_engine(database_config.config)

            with make_conn(database_config, engine) as db_conn:
                logger.info("Preparing database %r...", db_name)

                engine.check_database(db_conn)
                prepare_database(
                    db_conn, engine, hs.config, data_stores=database_config.data_stores,
                )

                database = Database(hs, database_config, engine)

                if "main" in database_config.data_stores:
                    logger.info("Starting 'main' data store")

                    # Sanity check we don't try and configure the main store on
                    # multiple databases.
                    if self.main:
                        raise Exception("'main' data store already configured")

                    self.main = main_store_class(database, db_conn, hs)

                    # If we're on a process that can persist events also
                    # instantiate a `PersistEventsStore`
                    if hs.config.worker.writers.events == hs.get_instance_name():
                        self.persist_events = PersistEventsStore(
                            hs, database, self.main
                        )

                if "state" in database_config.data_stores:
                    logger.info("Starting 'state' data store")

                    # Sanity check we don't try and configure the state store on
                    # multiple databases.
                    if self.state:
                        raise Exception("'state' data store already configured")

                    self.state = StateGroupDataStore(database, db_conn, hs)

                db_conn.commit()

                self.databases.append(database)

                logger.info("Database %r prepared", db_name)

        # Sanity check that we have actually configured all the required stores.
        if not self.main:
            raise Exception("No 'main' data store configured")

        if not self.state:
            raise Exception("No 'main' data store configured")
