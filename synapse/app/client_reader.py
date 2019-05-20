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
import logging
import sys

from twisted.internet import reactor
from twisted.web.resource import NoResource

import synapse
from synapse import events
from synapse.app import _base
from synapse.config._base import ConfigError
from synapse.config.homeserver import HomeServerConfig
from synapse.config.logger import setup_logging
from synapse.http.server import JsonResource
from synapse.http.site import SynapseSite
from synapse.metrics import RegistryProxy
from synapse.metrics.resource import METRICS_PREFIX, MetricsResource
from synapse.replication.slave.storage._base import BaseSlavedStore
from synapse.replication.slave.storage.account_data import SlavedAccountDataStore
from synapse.replication.slave.storage.appservice import SlavedApplicationServiceStore
from synapse.replication.slave.storage.client_ips import SlavedClientIpStore
from synapse.replication.slave.storage.deviceinbox import SlavedDeviceInboxStore
from synapse.replication.slave.storage.devices import SlavedDeviceStore
from synapse.replication.slave.storage.directory import DirectoryStore
from synapse.replication.slave.storage.events import SlavedEventStore
from synapse.replication.slave.storage.keys import SlavedKeyStore
from synapse.replication.slave.storage.push_rule import SlavedPushRuleStore
from synapse.replication.slave.storage.receipts import SlavedReceiptsStore
from synapse.replication.slave.storage.registration import SlavedRegistrationStore
from synapse.replication.slave.storage.room import RoomStore
from synapse.replication.slave.storage.transactions import SlavedTransactionStore
from synapse.replication.tcp.client import ReplicationClientHandler
from synapse.rest.client.v1.login import LoginRestServlet
from synapse.rest.client.v1.push_rule import PushRuleRestServlet
from synapse.rest.client.v1.room import (
    JoinedRoomMemberListRestServlet,
    PublicRoomListRestServlet,
    RoomEventContextServlet,
    RoomMemberListRestServlet,
    RoomStateRestServlet,
)
from synapse.rest.client.v1.voip import VoipRestServlet
from synapse.rest.client.v2_alpha.account import ThreepidRestServlet
from synapse.rest.client.v2_alpha.keys import KeyChangesServlet, KeyQueryServlet
from synapse.rest.client.v2_alpha.register import RegisterRestServlet
from synapse.rest.client.versions import VersionsRestServlet
from synapse.server import HomeServer
from synapse.storage.engines import create_engine
from synapse.util.httpresourcetree import create_resource_tree
from synapse.util.logcontext import LoggingContext
from synapse.util.manhole import manhole
from synapse.util.versionstring import get_version_string

logger = logging.getLogger("synapse.app.client_reader")


class ClientReaderSlavedStore(
    SlavedDeviceInboxStore,
    SlavedDeviceStore,
    SlavedReceiptsStore,
    SlavedPushRuleStore,
    SlavedAccountDataStore,
    SlavedEventStore,
    SlavedKeyStore,
    RoomStore,
    DirectoryStore,
    SlavedApplicationServiceStore,
    SlavedRegistrationStore,
    SlavedTransactionStore,
    SlavedClientIpStore,
    BaseSlavedStore,
):
    pass


class ClientReaderServer(HomeServer):
    DATASTORE_CLASS = ClientReaderSlavedStore

    def _listen_http(self, listener_config):
        port = listener_config["port"]
        bind_addresses = listener_config["bind_addresses"]
        site_tag = listener_config.get("tag", port)
        resources = {}
        for res in listener_config["resources"]:
            for name in res["names"]:
                if name == "metrics":
                    resources[METRICS_PREFIX] = MetricsResource(RegistryProxy)
                elif name == "client":
                    resource = JsonResource(self, canonical_json=False)

                    PublicRoomListRestServlet(self).register(resource)
                    RoomMemberListRestServlet(self).register(resource)
                    JoinedRoomMemberListRestServlet(self).register(resource)
                    RoomStateRestServlet(self).register(resource)
                    RoomEventContextServlet(self).register(resource)
                    RegisterRestServlet(self).register(resource)
                    LoginRestServlet(self).register(resource)
                    ThreepidRestServlet(self).register(resource)
                    KeyQueryServlet(self).register(resource)
                    KeyChangesServlet(self).register(resource)
                    VoipRestServlet(self).register(resource)
                    PushRuleRestServlet(self).register(resource)
                    VersionsRestServlet().register(resource)

                    resources.update({
                        "/_matrix/client": resource,
                    })

        root_resource = create_resource_tree(resources, NoResource())

        _base.listen_tcp(
            bind_addresses,
            port,
            SynapseSite(
                "synapse.access.http.%s" % (site_tag,),
                site_tag,
                listener_config,
                root_resource,
                self.version_string,
            )
        )

        logger.info("Synapse client reader now listening on port %d", port)

    def start_listening(self, listeners):
        for listener in listeners:
            if listener["type"] == "http":
                self._listen_http(listener)
            elif listener["type"] == "manhole":
                _base.listen_tcp(
                    listener["bind_addresses"],
                    listener["port"],
                    manhole(
                        username="matrix",
                        password="rabbithole",
                        globals={"hs": self},
                    )
                )
            elif listener["type"] == "metrics":
                if not self.get_config().enable_metrics:
                    logger.warn(("Metrics listener configured, but "
                                 "enable_metrics is not True!"))
                else:
                    _base.listen_metrics(listener["bind_addresses"],
                                         listener["port"])
            else:
                logger.warn("Unrecognized listener type: %s", listener["type"])

        self.get_tcp_replication().start_replication(self)

    def build_tcp_replication(self):
        return ReplicationClientHandler(self.get_datastore())


def start(config_options):
    try:
        config = HomeServerConfig.load_config(
            "Synapse client reader", config_options
        )
    except ConfigError as e:
        sys.stderr.write("\n" + str(e) + "\n")
        sys.exit(1)

    assert config.worker_app == "synapse.app.client_reader"

    setup_logging(config, use_worker_options=True)

    events.USE_FROZEN_DICTS = config.use_frozen_dicts

    database_engine = create_engine(config.database_config)

    ss = ClientReaderServer(
        config.server_name,
        db_config=config.database_config,
        config=config,
        version_string="Synapse/" + get_version_string(synapse),
        database_engine=database_engine,
    )

    ss.setup()
    reactor.callWhenRunning(_base.start, ss, config.worker_listeners)

    _base.start_worker_reactor("synapse-client-reader", config)


if __name__ == '__main__':
    with LoggingContext("main"):
        start(sys.argv[1:])
