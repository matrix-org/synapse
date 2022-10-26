# Copyright 2016 OpenMarket Ltd
# Copyright 2020 The Matrix.org Foundation C.I.C.
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
from typing import Dict, List, Optional, Tuple

from twisted.internet import address
from twisted.web.resource import Resource

import synapse
import synapse.events
from synapse.api.errors import HttpResponseException, RequestSendFailed, SynapseError
from synapse.api.urls import (
    CLIENT_API_PREFIX,
    FEDERATION_PREFIX,
    LEGACY_MEDIA_PREFIX,
    MEDIA_R0_PREFIX,
    MEDIA_V3_PREFIX,
    SERVER_KEY_PREFIX,
)
from synapse.app import _base
from synapse.app._base import (
    handle_startup_exception,
    max_request_body_size,
    redirect_stdio_to_logs,
    register_start,
)
from synapse.config._base import ConfigError
from synapse.config.homeserver import HomeServerConfig
from synapse.config.logger import setup_logging
from synapse.config.server import ListenerConfig
from synapse.federation.transport.server import TransportLayerServer
from synapse.http.server import JsonResource, OptionsResource
from synapse.http.servlet import RestServlet, parse_json_object_from_request
from synapse.http.site import SynapseRequest, SynapseSite
from synapse.logging.context import LoggingContext
from synapse.metrics import METRICS_PREFIX, MetricsResource, RegistryProxy
from synapse.replication.http import REPLICATION_PREFIX, ReplicationRestResource
from synapse.replication.slave.storage.devices import SlavedDeviceStore
from synapse.replication.slave.storage.events import SlavedEventStore
from synapse.replication.slave.storage.filtering import SlavedFilteringStore
from synapse.replication.slave.storage.keys import SlavedKeyStore
from synapse.replication.slave.storage.push_rule import SlavedPushRuleStore
from synapse.replication.slave.storage.pushers import SlavedPusherStore
from synapse.rest.admin import register_servlets_for_media_repo
from synapse.rest.client import (
    account_data,
    events,
    initial_sync,
    login,
    presence,
    profile,
    push_rule,
    read_marker,
    receipts,
    relations,
    room,
    room_batch,
    room_keys,
    sendtodevice,
    sync,
    tags,
    user_directory,
    versions,
    voip,
)
from synapse.rest.client._base import client_patterns
from synapse.rest.client.account import ThreepidRestServlet, WhoamiRestServlet
from synapse.rest.client.devices import DevicesRestServlet
from synapse.rest.client.keys import (
    KeyChangesServlet,
    KeyQueryServlet,
    OneTimeKeyServlet,
)
from synapse.rest.client.register import (
    RegisterRestServlet,
    RegistrationTokenValidityRestServlet,
)
from synapse.rest.health import HealthResource
from synapse.rest.key.v2 import KeyResource
from synapse.rest.synapse.client import build_synapse_client_resource_tree
from synapse.rest.well_known import well_known_resource
from synapse.server import HomeServer
from synapse.storage.databases.main.account_data import AccountDataWorkerStore
from synapse.storage.databases.main.appservice import (
    ApplicationServiceTransactionWorkerStore,
    ApplicationServiceWorkerStore,
)
from synapse.storage.databases.main.censor_events import CensorEventsStore
from synapse.storage.databases.main.client_ips import ClientIpWorkerStore
from synapse.storage.databases.main.deviceinbox import DeviceInboxWorkerStore
from synapse.storage.databases.main.directory import DirectoryWorkerStore
from synapse.storage.databases.main.e2e_room_keys import EndToEndRoomKeyStore
from synapse.storage.databases.main.lock import LockStore
from synapse.storage.databases.main.media_repository import MediaRepositoryStore
from synapse.storage.databases.main.metrics import ServerMetricsStore
from synapse.storage.databases.main.monthly_active_users import (
    MonthlyActiveUsersWorkerStore,
)
from synapse.storage.databases.main.presence import PresenceStore
from synapse.storage.databases.main.profile import ProfileWorkerStore
from synapse.storage.databases.main.receipts import ReceiptsWorkerStore
from synapse.storage.databases.main.registration import RegistrationWorkerStore
from synapse.storage.databases.main.room import RoomWorkerStore
from synapse.storage.databases.main.room_batch import RoomBatchStore
from synapse.storage.databases.main.search import SearchStore
from synapse.storage.databases.main.session import SessionStore
from synapse.storage.databases.main.stats import StatsStore
from synapse.storage.databases.main.tags import TagsWorkerStore
from synapse.storage.databases.main.transactions import TransactionWorkerStore
from synapse.storage.databases.main.ui_auth import UIAuthWorkerStore
from synapse.storage.databases.main.user_directory import UserDirectoryStore
from synapse.types import JsonDict
from synapse.util import SYNAPSE_VERSION
from synapse.util.httpresourcetree import create_resource_tree

logger = logging.getLogger("synapse.app.generic_worker")


class KeyUploadServlet(RestServlet):
    """An implementation of the `KeyUploadServlet` that responds to read only
    requests, but otherwise proxies through to the master instance.
    """

    PATTERNS = client_patterns("/keys/upload(/(?P<device_id>[^/]+))?$")

    def __init__(self, hs: HomeServer):
        """
        Args:
            hs: server
        """
        super().__init__()
        self.auth = hs.get_auth()
        self.store = hs.get_datastores().main
        self.http_client = hs.get_simple_http_client()
        self.main_uri = hs.config.worker.worker_main_http_uri

    async def on_POST(
        self, request: SynapseRequest, device_id: Optional[str]
    ) -> Tuple[int, JsonDict]:
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

            # Proxy headers from the original request, such as the auth headers
            # (in case the access token is there) and the original IP /
            # User-Agent of the request.
            headers: Dict[bytes, List[bytes]] = {
                header: list(request.requestHeaders.getRawHeaders(header, []))
                for header in (b"Authorization", b"User-Agent")
            }
            # Add the previous hop to the X-Forwarded-For header.
            x_forwarded_for = list(
                request.requestHeaders.getRawHeaders(b"X-Forwarded-For", [])
            )
            # we use request.client here, since we want the previous hop, not the
            # original client (as returned by request.getClientAddress()).
            if isinstance(request.client, (address.IPv4Address, address.IPv6Address)):
                previous_host = request.client.host.encode("ascii")
                # If the header exists, add to the comma-separated list of the first
                # instance of the header. Otherwise, generate a new header.
                if x_forwarded_for:
                    x_forwarded_for = [x_forwarded_for[0] + b", " + previous_host]
                    x_forwarded_for.extend(x_forwarded_for[1:])
                else:
                    x_forwarded_for = [previous_host]
            headers[b"X-Forwarded-For"] = x_forwarded_for

            # Replicate the original X-Forwarded-Proto header. Note that
            # XForwardedForRequest overrides isSecure() to give us the original protocol
            # used by the client, as opposed to the protocol used by our upstream proxy
            # - which is what we want here.
            headers[b"X-Forwarded-Proto"] = [
                b"https" if request.isSecure() else b"http"
            ]

            try:
                result = await self.http_client.post_json_get_json(
                    self.main_uri + request.uri.decode("ascii"), body, headers=headers
                )
            except HttpResponseException as e:
                raise e.to_synapse_error() from e
            except RequestSendFailed as e:
                raise SynapseError(502, "Failed to talk to master") from e

            return 200, result
        else:
            # Just interested in counts.
            result = await self.store.count_e2e_one_time_keys(user_id, device_id)
            return 200, {"one_time_key_counts": result}


class GenericWorkerSlavedStore(
    # FIXME(#3714): We need to add UserDirectoryStore as we write directly
    # rather than going via the correct worker.
    UserDirectoryStore,
    StatsStore,
    UIAuthWorkerStore,
    EndToEndRoomKeyStore,
    PresenceStore,
    DeviceInboxWorkerStore,
    SlavedDeviceStore,
    SlavedPushRuleStore,
    TagsWorkerStore,
    AccountDataWorkerStore,
    SlavedPusherStore,
    CensorEventsStore,
    ClientIpWorkerStore,
    SlavedEventStore,
    SlavedKeyStore,
    RoomWorkerStore,
    RoomBatchStore,
    DirectoryWorkerStore,
    ApplicationServiceTransactionWorkerStore,
    ApplicationServiceWorkerStore,
    ProfileWorkerStore,
    SlavedFilteringStore,
    MonthlyActiveUsersWorkerStore,
    MediaRepositoryStore,
    ServerMetricsStore,
    ReceiptsWorkerStore,
    RegistrationWorkerStore,
    SearchStore,
    TransactionWorkerStore,
    LockStore,
    SessionStore,
):
    # Properties that multiple storage classes define. Tell mypy what the
    # expected type is.
    server_name: str
    config: HomeServerConfig


class GenericWorkerServer(HomeServer):
    DATASTORE_CLASS = GenericWorkerSlavedStore  # type: ignore

    def _listen_http(self, listener_config: ListenerConfig) -> None:
        port = listener_config.port
        bind_addresses = listener_config.bind_addresses

        assert listener_config.http_options is not None

        site_tag = listener_config.http_options.tag
        if site_tag is None:
            site_tag = str(port)

        # We always include a health resource.
        resources: Dict[str, Resource] = {"/health": HealthResource()}

        for res in listener_config.http_options.resources:
            for name in res.names:
                if name == "metrics":
                    resources[METRICS_PREFIX] = MetricsResource(RegistryProxy)
                elif name == "client":
                    resource = JsonResource(self, canonical_json=False)

                    RegisterRestServlet(self).register(resource)
                    RegistrationTokenValidityRestServlet(self).register(resource)
                    login.register_servlets(self, resource)
                    ThreepidRestServlet(self).register(resource)
                    WhoamiRestServlet(self).register(resource)
                    DevicesRestServlet(self).register(resource)

                    # Read-only
                    KeyUploadServlet(self).register(resource)
                    KeyQueryServlet(self).register(resource)
                    KeyChangesServlet(self).register(resource)
                    OneTimeKeyServlet(self).register(resource)

                    voip.register_servlets(self, resource)
                    push_rule.register_servlets(self, resource)
                    versions.register_servlets(self, resource)

                    profile.register_servlets(self, resource)

                    sync.register_servlets(self, resource)
                    events.register_servlets(self, resource)
                    room.register_servlets(self, resource, is_worker=True)
                    relations.register_servlets(self, resource)
                    room.register_deprecated_servlets(self, resource)
                    initial_sync.register_servlets(self, resource)
                    room_batch.register_servlets(self, resource)
                    room_keys.register_servlets(self, resource)
                    tags.register_servlets(self, resource)
                    account_data.register_servlets(self, resource)
                    receipts.register_servlets(self, resource)
                    read_marker.register_servlets(self, resource)

                    sendtodevice.register_servlets(self, resource)

                    user_directory.register_servlets(self, resource)

                    presence.register_servlets(self, resource)

                    resources[CLIENT_API_PREFIX] = resource

                    resources.update(build_synapse_client_resource_tree(self))
                    resources["/.well-known"] = well_known_resource(self)

                elif name == "federation":
                    resources[FEDERATION_PREFIX] = TransportLayerServer(self)
                elif name == "media":
                    if self.config.media.can_load_media_repo:
                        media_repo = self.get_media_repository_resource()

                        # We need to serve the admin servlets for media on the
                        # worker.
                        admin_resource = JsonResource(self, canonical_json=False)
                        register_servlets_for_media_repo(self, admin_resource)

                        resources.update(
                            {
                                MEDIA_R0_PREFIX: media_repo,
                                MEDIA_V3_PREFIX: media_repo,
                                LEGACY_MEDIA_PREFIX: media_repo,
                                "/_synapse/admin": admin_resource,
                            }
                        )
                    else:
                        logger.warning(
                            "A 'media' listener is configured but the media"
                            " repository is disabled. Ignoring."
                        )

                if name == "openid" and "federation" not in res.names:
                    # Only load the openid resource separately if federation resource
                    # is not specified since federation resource includes openid
                    # resource.
                    resources[FEDERATION_PREFIX] = TransportLayerServer(
                        self, servlet_groups=["openid"]
                    )

                if name in ["keys", "federation"]:
                    resources[SERVER_KEY_PREFIX] = KeyResource(self)

                if name == "replication":
                    resources[REPLICATION_PREFIX] = ReplicationRestResource(self)

        # Attach additional resources registered by modules.
        resources.update(self._module_web_resources)
        self._module_web_resources_consumed = True

        root_resource = create_resource_tree(resources, OptionsResource())

        _base.listen_tcp(
            bind_addresses,
            port,
            SynapseSite(
                "synapse.access.http.%s" % (site_tag,),
                site_tag,
                listener_config,
                root_resource,
                self.version_string,
                max_request_body_size=max_request_body_size(self.config),
                reactor=self.get_reactor(),
            ),
            reactor=self.get_reactor(),
        )

        logger.info("Synapse worker now listening on port %d", port)

    def start_listening(self) -> None:
        for listener in self.config.worker.worker_listeners:
            if listener.type == "http":
                self._listen_http(listener)
            elif listener.type == "manhole":
                _base.listen_manhole(
                    listener.bind_addresses,
                    listener.port,
                    manhole_settings=self.config.server.manhole_settings,
                    manhole_globals={"hs": self},
                )
            elif listener.type == "metrics":
                if not self.config.metrics.enable_metrics:
                    logger.warning(
                        "Metrics listener configured, but "
                        "enable_metrics is not True!"
                    )
                else:
                    _base.listen_metrics(
                        listener.bind_addresses,
                        listener.port,
                        enable_legacy_metric_names=self.config.metrics.enable_legacy_metrics,
                    )
            else:
                logger.warning("Unsupported listener type: %s", listener.type)

        self.get_replication_command_handler().start_replication(self)


def start(config_options: List[str]) -> None:
    try:
        config = HomeServerConfig.load_config("Synapse worker", config_options)
    except ConfigError as e:
        sys.stderr.write("\n" + str(e) + "\n")
        sys.exit(1)

    # For backwards compatibility let any of the old app names.
    assert config.worker.worker_app in (
        "synapse.app.appservice",
        "synapse.app.client_reader",
        "synapse.app.event_creator",
        "synapse.app.federation_reader",
        "synapse.app.federation_sender",
        "synapse.app.frontend_proxy",
        "synapse.app.generic_worker",
        "synapse.app.media_repository",
        "synapse.app.pusher",
        "synapse.app.synchrotron",
        "synapse.app.user_dir",
    )

    if config.experimental.faster_joins_enabled:
        raise ConfigError(
            "You have enabled the experimental `faster_joins` config option, but it is "
            "not compatible with worker deployments yet. Please disable `faster_joins` "
            "or run Synapse as a single process deployment instead."
        )

    synapse.events.USE_FROZEN_DICTS = config.server.use_frozen_dicts
    synapse.util.caches.TRACK_MEMORY_USAGE = config.caches.track_memory_usage

    if config.server.gc_seconds:
        synapse.metrics.MIN_TIME_BETWEEN_GCS = config.server.gc_seconds

    hs = GenericWorkerServer(
        config.server.server_name,
        config=config,
        version_string=f"Synapse/{SYNAPSE_VERSION}",
    )

    setup_logging(hs, config, use_worker_options=True)

    try:
        hs.setup()

        # Ensure the replication streamer is always started in case we write to any
        # streams. Will no-op if no streams can be written to by this worker.
        hs.get_replication_streamer()
    except Exception as e:
        handle_startup_exception(e)

    register_start(_base.start, hs)

    # redirect stdio to the logs, if configured.
    if not hs.config.logging.no_redirect_stdio:
        redirect_stdio_to_logs()

    _base.start_worker_reactor("synapse-generic-worker", config)


def main() -> None:
    with LoggingContext("main"):
        start(sys.argv[1:])


if __name__ == "__main__":
    main()
