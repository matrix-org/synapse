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
from synapse.api.errors import HttpResponseException, SynapseError
from synapse.api.urls import (
    CLIENT_API_PREFIX,
    FEDERATION_PREFIX,
    LEGACY_MEDIA_PREFIX,
    MEDIA_PREFIX,
    SERVER_KEY_V2_PREFIX,
)
from synapse.app import _base
from synapse.config._base import ConfigError
from synapse.config.homeserver import HomeServerConfig
from synapse.config.logger import setup_logging
from synapse.federation.transport.server import TransportLayerServer
from synapse.http.server import JsonResource
from synapse.http.servlet import RestServlet, parse_json_object_from_request
from synapse.http.site import SynapseSite
from synapse.logging.context import LoggingContext
from synapse.metrics import METRICS_PREFIX, MetricsResource, RegistryProxy
from synapse.replication.slave.storage._base import BaseSlavedStore
from synapse.replication.slave.storage.account_data import SlavedAccountDataStore
from synapse.replication.slave.storage.appservice import SlavedApplicationServiceStore
from synapse.replication.slave.storage.client_ips import SlavedClientIpStore
from synapse.replication.slave.storage.deviceinbox import SlavedDeviceInboxStore
from synapse.replication.slave.storage.devices import SlavedDeviceStore
from synapse.replication.slave.storage.directory import DirectoryStore
from synapse.replication.slave.storage.events import SlavedEventStore
from synapse.replication.slave.storage.groups import SlavedGroupServerStore
from synapse.replication.slave.storage.keys import SlavedKeyStore
from synapse.replication.slave.storage.profile import SlavedProfileStore
from synapse.replication.slave.storage.push_rule import SlavedPushRuleStore
from synapse.replication.slave.storage.pushers import SlavedPusherStore
from synapse.replication.slave.storage.receipts import SlavedReceiptsStore
from synapse.replication.slave.storage.registration import SlavedRegistrationStore
from synapse.replication.slave.storage.room import RoomStore
from synapse.replication.slave.storage.transactions import SlavedTransactionStore
from synapse.replication.tcp.client import ReplicationClientHandler
from synapse.rest.admin import register_servlets_for_media_repo
from synapse.rest.client.v1.login import LoginRestServlet
from synapse.rest.client.v1.profile import (
    ProfileAvatarURLRestServlet,
    ProfileDisplaynameRestServlet,
    ProfileRestServlet,
)
from synapse.rest.client.v1.push_rule import PushRuleRestServlet
from synapse.rest.client.v1.room import (
    JoinedRoomMemberListRestServlet,
    JoinRoomAliasServlet,
    PublicRoomListRestServlet,
    RoomEventContextServlet,
    RoomMemberListRestServlet,
    RoomMembershipRestServlet,
    RoomMessageListRestServlet,
    RoomSendEventRestServlet,
    RoomStateEventRestServlet,
    RoomStateRestServlet,
)
from synapse.rest.client.v1.voip import VoipRestServlet
from synapse.rest.client.v2_alpha import groups
from synapse.rest.client.v2_alpha._base import client_patterns
from synapse.rest.client.v2_alpha.account import ThreepidRestServlet
from synapse.rest.client.v2_alpha.keys import KeyChangesServlet, KeyQueryServlet
from synapse.rest.client.v2_alpha.register import RegisterRestServlet
from synapse.rest.client.versions import VersionsRestServlet
from synapse.rest.key.v2 import KeyApiV2Resource
from synapse.server import HomeServer
from synapse.storage.data_stores.main.media_repository import MediaRepositoryStore
from synapse.storage.data_stores.main.monthly_active_users import (
    MonthlyActiveUsersWorkerStore,
)
from synapse.storage.data_stores.main.user_directory import UserDirectoryStore
from synapse.util.httpresourcetree import create_resource_tree
from synapse.util.manhole import manhole
from synapse.util.versionstring import get_version_string

logger = logging.getLogger("synapse.app.generic_worker")


class PresenceStatusStubServlet(RestServlet):
    """If presence is disabled this servlet can be used to stub out setting
    presence status, while proxying the getters to the master instance.
    """

    PATTERNS = client_patterns("/presence/(?P<user_id>[^/]*)/status")

    def __init__(self, hs):
        super(PresenceStatusStubServlet, self).__init__()
        self.http_client = hs.get_simple_http_client()
        self.auth = hs.get_auth()
        self.main_uri = hs.config.worker_main_http_uri

    async def on_GET(self, request, user_id):
        # Pass through the auth headers, if any, in case the access token
        # is there.
        auth_headers = request.requestHeaders.getRawHeaders("Authorization", [])
        headers = {"Authorization": auth_headers}

        try:
            result = await self.http_client.get_json(
                self.main_uri + request.uri.decode("ascii"), headers=headers
            )
        except HttpResponseException as e:
            raise e.to_synapse_error()

        return 200, result

    async def on_PUT(self, request, user_id):
        await self.auth.get_user_by_req(request)
        return 200, {}


class KeyUploadServlet(RestServlet):
    """An implementation of the `KeyUploadServlet` that responds to read only
    requests, but otherwise proxies through to the master instance.
    """

    PATTERNS = client_patterns("/keys/upload(/(?P<device_id>[^/]+))?$")

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

    async def on_POST(self, request, device_id):
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        user_id = requester.user.to_string()
        body = parse_json_object_from_request(request)

        if device_id is not None:
            # passing the device_id here is deprecated; however, we allow it
            # for now for compatibility with older clients.
            if requester.device_id is not None and device_id != requester.device_id:
                logger.warning(
                    "Client uploading keys for a different device "
                    "(logged in as %s, uploading for %s)",
                    requester.device_id,
                    device_id,
                )
        else:
            device_id = requester.device_id

        if device_id is None:
            raise SynapseError(
                400, "To upload keys, you must pass device_id when authenticating"
            )

        if body:
            # They're actually trying to upload something, proxy to main synapse.
            # Pass through the auth headers, if any, in case the access token
            # is there.
            auth_headers = request.requestHeaders.getRawHeaders(b"Authorization", [])
            headers = {"Authorization": auth_headers}
            result = await self.http_client.post_json_get_json(
                self.main_uri + request.uri.decode("ascii"), body, headers=headers
            )

            return 200, result
        else:
            # Just interested in counts.
            result = await self.store.count_e2e_one_time_keys(user_id, device_id)
            return 200, {"one_time_key_counts": result}


class GenericWorkerSlavedStore(
    # FIXME(#3714): We need to add UserDirectoryStore as we write directly
    # rather than going via the correct worker.
    UserDirectoryStore,
    SlavedDeviceInboxStore,
    SlavedDeviceStore,
    SlavedReceiptsStore,
    SlavedPushRuleStore,
    SlavedGroupServerStore,
    SlavedAccountDataStore,
    SlavedPusherStore,
    SlavedEventStore,
    SlavedKeyStore,
    RoomStore,
    DirectoryStore,
    SlavedApplicationServiceStore,
    SlavedRegistrationStore,
    SlavedTransactionStore,
    SlavedProfileStore,
    SlavedClientIpStore,
    MonthlyActiveUsersWorkerStore,
    MediaRepositoryStore,
    BaseSlavedStore,
):
    pass


class GenericWorkerServer(HomeServer):
    DATASTORE_CLASS = GenericWorkerSlavedStore

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
                    RoomMessageListRestServlet(self).register(resource)
                    RegisterRestServlet(self).register(resource)
                    LoginRestServlet(self).register(resource)
                    ThreepidRestServlet(self).register(resource)
                    KeyQueryServlet(self).register(resource)
                    KeyChangesServlet(self).register(resource)
                    VoipRestServlet(self).register(resource)
                    PushRuleRestServlet(self).register(resource)
                    VersionsRestServlet(self).register(resource)
                    RoomSendEventRestServlet(self).register(resource)
                    RoomMembershipRestServlet(self).register(resource)
                    RoomStateEventRestServlet(self).register(resource)
                    JoinRoomAliasServlet(self).register(resource)
                    ProfileAvatarURLRestServlet(self).register(resource)
                    ProfileDisplaynameRestServlet(self).register(resource)
                    ProfileRestServlet(self).register(resource)
                    KeyUploadServlet(self).register(resource)

                    # If presence is disabled, use the stub servlet that does
                    # not allow sending presence
                    if not self.config.use_presence:
                        PresenceStatusStubServlet(self).register(resource)

                    groups.register_servlets(self, resource)

                    resources.update({CLIENT_API_PREFIX: resource})
                elif name == "federation":
                    resources.update({FEDERATION_PREFIX: TransportLayerServer(self)})
                elif name == "media":
                    media_repo = self.get_media_repository_resource()

                    # We need to serve the admin servlets for media on the
                    # worker.
                    admin_resource = JsonResource(self, canonical_json=False)
                    register_servlets_for_media_repo(self, admin_resource)

                    resources.update(
                        {
                            MEDIA_PREFIX: media_repo,
                            LEGACY_MEDIA_PREFIX: media_repo,
                            "/_synapse/admin": admin_resource,
                        }
                    )

                if name == "openid" and "federation" not in res["names"]:
                    # Only load the openid resource separately if federation resource
                    # is not specified since federation resource includes openid
                    # resource.
                    resources.update(
                        {
                            FEDERATION_PREFIX: TransportLayerServer(
                                self, servlet_groups=["openid"]
                            )
                        }
                    )

                if name in ["keys", "federation"]:
                    resources[SERVER_KEY_V2_PREFIX] = KeyApiV2Resource(self)

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
            reactor=self.get_reactor(),
        )

        logger.info("Synapse worker now listening on port %d", port)

    def start_listening(self, listeners):
        for listener in listeners:
            if listener["type"] == "http":
                self._listen_http(listener)
            elif listener["type"] == "manhole":
                _base.listen_tcp(
                    listener["bind_addresses"],
                    listener["port"],
                    manhole(
                        username="matrix", password="rabbithole", globals={"hs": self}
                    ),
                )
            elif listener["type"] == "metrics":
                if not self.get_config().enable_metrics:
                    logger.warning(
                        (
                            "Metrics listener configured, but "
                            "enable_metrics is not True!"
                        )
                    )
                else:
                    _base.listen_metrics(listener["bind_addresses"], listener["port"])
            else:
                logger.warning("Unrecognized listener type: %s", listener["type"])

        self.get_tcp_replication().start_replication(self)

    def build_tcp_replication(self):
        return ReplicationClientHandler(self.get_datastore())


def start(config_options):
    try:
        config = HomeServerConfig.load_config("Synapse worker", config_options)
    except ConfigError as e:
        sys.stderr.write("\n" + str(e) + "\n")
        sys.exit(1)

    # For backwards compatibility let any of the old app names.
    assert config.worker_app in (
        "synapse.app.client_reader",
        "synapse.app.event_creator",
        "synapse.app.federation_reader",
        "synapse.app.frontend_proxy",
        "synapse.app.generic_worker",
        "synapse.app.media_repository",
    )

    events.USE_FROZEN_DICTS = config.use_frozen_dicts

    ss = GenericWorkerServer(
        config.server_name,
        config=config,
        version_string="Synapse/" + get_version_string(synapse),
    )

    setup_logging(ss, config, use_worker_options=True)

    ss.setup()
    reactor.addSystemEventTrigger(
        "before", "startup", _base.start, ss, config.worker_listeners
    )

    _base.start_worker_reactor("synapse-generic-worker", config)


if __name__ == "__main__":
    with LoggingContext("main"):
        start(sys.argv[1:])
