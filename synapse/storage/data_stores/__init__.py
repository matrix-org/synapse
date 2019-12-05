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

from synapse.storage.prepare_database import prepare_database

logger = logging.getLogger(__name__)


class DataStores(object):
    """The various data stores.

    These are low level interfaces to physical databases.

    Attributes:
        main (DataStore)
    """

    def __init__(self, main_store_class, hs):
        # Note we pass in the main store here as workers use a different main
        # store.

        # This is a bit convoluted as we need to figure out which stores are in
        # which databases.

        db_to_store = {}
        for store_name in ("main",):
            db_to_store.setdefault(hs.config.data_stores[store_name], []).append(
                store_name
            )

        for db_name, store_names in db_to_store.items():
            database = hs.config.databases[db_name]
            with database.make_conn() as db_conn:
                logger.info("Preparing database %r...", db_name)
                database.engine.check_database(db_conn.cursor())
                prepare_database(
                    db_conn, database.engine, hs.config, data_stores=store_names
                )

                if "main" in store_names:
                    logger.info("Starting 'main' data store")
                    self.main = main_store_class(database, db_conn, hs)

                db_conn.commit()

                logger.info("Database %r prepared", db_name)
