#!/usr/bin/env python
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

import synapse

from synapse.server import HomeServer
from synapse.util.versionstring import get_version_string
from synapse.config._base import ConfigError
from synapse.config.database import DatabaseConfig
from synapse.config.logger import LoggingConfig
from synapse.replication.slave.storage.events import SlavedEventStore
from synapse.replication.slave.storage.pushers import SlavedPusherStore
from synapse.replication.slave.storage.receipts import SlavedReceiptsStore
from synapse.storage.engines import create_engine
from synapse.storage import DataStore
from synapse.util.async import sleep
from synapse.util.logcontext import (LoggingContext, preserve_fn)

from twisted.internet import reactor, defer

import sys
import logging

logger = logging.getLogger("synapse.app.pusher")


class SlaveConfig(DatabaseConfig):
    def read_config(self, config):
        self.replication_url = config["replication_url"]
        self.server_name = config["server_name"]
        self.use_insecure_ssl_client_just_for_testing_do_not_use = config.get(
            "use_insecure_ssl_client_just_for_testing_do_not_use", False
        )
        self.user_agent_suffix = None
        self.start_pushers = True

    def default_config(self, **kwargs):
        return """\
        ## Slave ##
        #replication_url: https://localhost:{replication_port}/_synapse/replication

        report_stats: False
        """


class PusherSlaveConfig(SlaveConfig, LoggingConfig):
    pass


class PusherSlaveStore(
    SlavedEventStore, SlavedPusherStore, SlavedReceiptsStore
):
    update_pusher_last_stream_ordering_and_success = (
        DataStore.update_pusher_last_stream_ordering_and_success.__func__
    )


class PusherServer(HomeServer):

    def get_db_conn(self, run_new_connection=True):
        # Any param beginning with cp_ is a parameter for adbapi, and should
        # not be passed to the database engine.
        db_params = {
            k: v for k, v in self.db_config.get("args", {}).items()
            if not k.startswith("cp_")
        }
        db_conn = self.database_engine.module.connect(**db_params)

        if run_new_connection:
            self.database_engine.on_new_connection(db_conn)
        return db_conn

    def setup(self):
        logger.info("Setting up.")
        self.datastore = PusherSlaveStore(self.get_db_conn(), self)
        logger.info("Finished setting up.")

    def remove_pusher(self, app_id, push_key, user_id):
        http_client = self.get_simple_http_client()
        replication_url = self.config.replication_url
        url = replication_url + "/remove_pushers"
        return http_client.post_json_get_json(url, {
            "remove": [{
                "app_id": app_id,
                "push_key": push_key,
                "user_id": user_id,
            }]
        })

    @defer.inlineCallbacks
    def replicate(self):
        http_client = self.get_simple_http_client()
        store = self.get_datastore()
        replication_url = self.config.replication_url
        pusher_pool = self.get_pusherpool()

        def stop_pusher(user_id, app_id, pushkey):
            key = "%s:%s" % (app_id, pushkey)
            pushers_for_user = pusher_pool.pushers.get(user_id, {})
            pusher = pushers_for_user.pop(key, None)
            if pusher is None:
                return
            logger.info("Stopping pusher %r / %r", user_id, key)
            pusher.on_stop()

        def start_pusher(user_id, app_id, pushkey):
            key = "%s:%s" % (app_id, pushkey)
            logger.info("Starting pusher %r / %r", user_id, key)
            return pusher_pool._refresh_pusher(app_id, pushkey, user_id)

        @defer.inlineCallbacks
        def poke_pushers(results):
            pushers_rows = set(
                map(tuple, results.get("pushers", {}).get("rows", []))
            )
            deleted_pushers_rows = set(
                map(tuple, results.get("deleted_pushers", {}).get("rows", []))
            )
            for row in sorted(pushers_rows | deleted_pushers_rows):
                if row in deleted_pushers_rows:
                    user_id, app_id, pushkey = row[1:4]
                    stop_pusher(user_id, app_id, pushkey)
                elif row in pushers_rows:
                    user_id = row[1]
                    app_id = row[5]
                    pushkey = row[8]
                    yield start_pusher(user_id, app_id, pushkey)

            stream = results.get("events")
            if stream:
                min_stream_id = stream["rows"][0][0]
                max_stream_id = stream["position"]
                preserve_fn(pusher_pool.on_new_notifications)(
                    min_stream_id, max_stream_id
                )

            stream = results.get("receipts")
            if stream:
                rows = stream["rows"]
                affected_room_ids = set(row[1] for row in rows)
                min_stream_id = rows[0][0]
                max_stream_id = stream["position"]
                preserve_fn(pusher_pool.on_new_receipts)(
                    min_stream_id, max_stream_id, affected_room_ids
                )

        while True:
            try:
                args = store.stream_positions()
                args["timeout"] = 30000
                result = yield http_client.get_json(replication_url, args=args)
                yield store.process_replication(result)
                poke_pushers(result)
            except:
                logger.exception("Error replicating from %r", replication_url)
                sleep(30)


def setup(config_options):
    try:
        config = PusherSlaveConfig.load_config(
            "Synapse pusher", config_options
        )
    except ConfigError as e:
        sys.stderr.write("\n" + e.message + "\n")
        sys.exit(1)

    config.setup_logging()

    database_engine = create_engine(config.database_config)

    ps = PusherServer(
        config.server_name,
        db_config=config.database_config,
        config=config,
        version_string=get_version_string("Synapse", synapse),
        database_engine=database_engine,
    )

    ps.setup()

    def start():
        ps.replicate()
        ps.get_pusherpool().start()
        ps.get_datastore().start_profiling()

    reactor.callWhenRunning(start)

    return ps


if __name__ == '__main__':
    with LoggingContext("main"):
        ps = setup(sys.argv[1:])
        reactor.run()
