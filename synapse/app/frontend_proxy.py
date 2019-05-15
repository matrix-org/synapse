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

from twisted.internet import defer, reactor
from twisted.web.resource import NoResource

import synapse
from synapse import events
from synapse.api.errors import HttpResponseException, SynapseError
from synapse.app import _base
from synapse.config._base import ConfigError
from synapse.config.homeserver import HomeServerConfig
from synapse.config.logger import setup_logging
from synapse.http.server import JsonResource
from synapse.http.servlet import RestServlet, parse_json_object_from_request
from synapse.http.site import SynapseSite
from synapse.metrics import RegistryProxy
from synapse.metrics.resource import METRICS_PREFIX, MetricsResource
from synapse.replication.slave.storage._base import BaseSlavedStore
from synapse.replication.slave.storage.appservice import SlavedApplicationServiceStore
from synapse.replication.slave.storage.client_ips import SlavedClientIpStore
from synapse.replication.slave.storage.devices import SlavedDeviceStore
from synapse.replication.slave.storage.registration import SlavedRegistrationStore
from synapse.replication.tcp.client import ReplicationClientHandler
from synapse.rest.client.v1.base import ClientV1RestServlet, client_path_patterns
from synapse.rest.client.v2_alpha._base import client_v2_patterns
from synapse.server import HomeServer
from synapse.storage.engines import create_engine
from synapse.util.httpresourcetree import create_resource_tree
from synapse.util.logcontext import LoggingContext
from synapse.util.manhole import manhole
from synapse.util.versionstring import get_version_string

logger = logging.getLogger("synapse.app.frontend_proxy")


class PresenceStatusStubServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns("/presence/(?P<user_id>[^/]*)/status")

    def __init__(self, hs):
        super(PresenceStatusStubServlet, self).__init__(hs)
        self.http_client = hs.get_simple_http_client()
        self.auth = hs.get_auth()
        self.main_uri = hs.config.worker_main_http_uri

    @defer.inlineCallbacks
    def on_GET(self, request, user_id):
        # Pass through the auth headers, if any, in case the access token
        # is there.
        auth_headers = request.requestHeaders.getRawHeaders("Authorization", [])
        headers = {
            "Authorization": auth_headers,
        }

        try:
            result = yield self.http_client.get_json(
                self.main_uri + request.uri.decode('ascii'),
                headers=headers,
            )
        except HttpResponseException as e:
            raise e.to_synapse_error()

        defer.returnValue((200, result))

    @defer.inlineCallbacks
    def on_PUT(self, request, user_id):
        yield self.auth.get_user_by_req(request)
        defer.returnValue((200, {}))


class KeyUploadServlet(RestServlet):
    PATTERNS = client_v2_patterns("/keys/upload(/(?P<device_id>[^/]+))?$")

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        super(KeyUploadServlet, self).__init__()
        self.auth = hs.get_auth()
        self.store = hs.get_datastore()
        self.http_client = hs.get_simple_http_client()
        self.main_uri = hs.config.worker_main_http_uri

    @defer.inlineCallbacks
    def on_POST(self, request, device_id):
        requester = yield self.auth.get_user_by_req(request, allow_guest=True)
        user_id = requester.user.to_string()
        body = parse_json_object_from_request(request)

        if device_id is not None:
            # passing the device_id here is deprecated; however, we allow it
            # for now for compatibility with older clients.
            if (requester.device_id is not None and
                    device_id != requester.device_id):
                logger.warning("Client uploading keys for a different device "
                               "(logged in as %s, uploading for %s)",
                               requester.device_id, device_id)
        else:
            device_id = requester.device_id

        if device_id is None:
            raise SynapseError(
                400,
                "To upload keys, you must pass device_id when authenticating"
            )

        if body:
            # They're actually trying to upload something, proxy to main synapse.
            # Pass through the auth headers, if any, in case the access token
            # is there.
            auth_headers = request.requestHeaders.getRawHeaders(b"Authorization", [])
            headers = {
                "Authorization": auth_headers,
            }
            result = yield self.http_client.post_json_get_json(
                self.main_uri + request.uri.decode('ascii'),
                body,
                headers=headers,
            )

            defer.returnValue((200, result))
        else:
            # Just interested in counts.
            result = yield self.store.count_e2e_one_time_keys(user_id, device_id)
            defer.returnValue((200, {"one_time_key_counts": result}))


class FrontendProxySlavedStore(
    SlavedDeviceStore,
    SlavedClientIpStore,
    SlavedApplicationServiceStore,
    SlavedRegistrationStore,
    BaseSlavedStore,
):
    pass


class FrontendProxyServer(HomeServer):
    DATASTORE_CLASS = FrontendProxySlavedStore

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
                    KeyUploadServlet(self).register(resource)

                    # If presence is disabled, use the stub servlet that does
                    # not allow sending presence
                    if not self.config.use_presence:
                        PresenceStatusStubServlet(self).register(resource)

                    resources.update({
                        "/_matrix/client/r0": resource,
                        "/_matrix/client/unstable": resource,
                        "/_matrix/client/v2_alpha": resource,
                        "/_matrix/client/api/v1": resource,
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
            ),
            reactor=self.get_reactor()
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
            "Synapse frontend proxy", config_options
        )
    except ConfigError as e:
        sys.stderr.write("\n" + str(e) + "\n")
        sys.exit(1)

    assert config.worker_app == "synapse.app.frontend_proxy"

    assert config.worker_main_http_uri is not None

    setup_logging(config, use_worker_options=True)

    events.USE_FROZEN_DICTS = config.use_frozen_dicts

    database_engine = create_engine(config.database_config)

    ss = FrontendProxyServer(
        config.server_name,
        db_config=config.database_config,
        config=config,
        version_string="Synapse/" + get_version_string(synapse),
        database_engine=database_engine,
    )

    ss.setup()
    reactor.callWhenRunning(_base.start, ss, config.worker_listeners)

    _base.start_worker_reactor("synapse-frontend-proxy", config)


if __name__ == '__main__':
    with LoggingContext("main"):
        start(sys.argv[1:])
