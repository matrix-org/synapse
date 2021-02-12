#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
import contextlib
import logging
import sys
from typing import Dict, Iterable, Optional, Set

from typing_extensions import ContextManager

from twisted.internet import address
from twisted.web.resource import IResource

import synapse
import synapse.events
from synapse.api.errors import HttpResponseException, RequestSendFailed, SynapseError
from synapse.api.urls import (
    CLIENT_API_PREFIX,
    FEDERATION_PREFIX,
    LEGACY_MEDIA_PREFIX,
    MEDIA_PREFIX,
    SERVER_KEY_V2_PREFIX,
)
from synapse.app import _base
from synapse.app._base import register_start
from synapse.config._base import ConfigError
from synapse.config.homeserver import HomeServerConfig
from synapse.config.logger import setup_logging
from synapse.config.server import ListenerConfig
from synapse.federation import send_queue
from synapse.federation.transport.server import TransportLayerServer
from synapse.handlers.presence import (
    BasePresenceHandler,
    PresenceState,
    get_interested_parties,
)
from synapse.http.server import JsonResource, OptionsResource
from synapse.http.servlet import RestServlet, parse_json_object_from_request
from synapse.http.site import SynapseSite
from synapse.logging.context import LoggingContext
from synapse.metrics import METRICS_PREFIX, MetricsResource, RegistryProxy
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.replication.http import REPLICATION_PREFIX, ReplicationRestResource
from synapse.replication.http.presence import (
    ReplicationBumpPresenceActiveTime,
    ReplicationPresenceSetState,
)
from synapse.replication.slave.storage._base import BaseSlavedStore
from synapse.replication.slave.storage.account_data import SlavedAccountDataStore
from synapse.replication.slave.storage.appservice import SlavedApplicationServiceStore
from synapse.replication.slave.storage.client_ips import SlavedClientIpStore
from synapse.replication.slave.storage.deviceinbox import SlavedDeviceInboxStore
from synapse.replication.slave.storage.devices import SlavedDeviceStore
from synapse.replication.slave.storage.directory import DirectoryStore
from synapse.replication.slave.storage.events import SlavedEventStore
from synapse.replication.slave.storage.filtering import SlavedFilteringStore
from synapse.replication.slave.storage.groups import SlavedGroupServerStore
from synapse.replication.slave.storage.keys import SlavedKeyStore
from synapse.replication.slave.storage.presence import SlavedPresenceStore
from synapse.replication.slave.storage.profile import SlavedProfileStore
from synapse.replication.slave.storage.push_rule import SlavedPushRuleStore
from synapse.replication.slave.storage.pushers import SlavedPusherStore
from synapse.replication.slave.storage.receipts import SlavedReceiptsStore
from synapse.replication.slave.storage.registration import SlavedRegistrationStore
from synapse.replication.slave.storage.room import RoomStore
from synapse.replication.slave.storage.transactions import SlavedTransactionStore
from synapse.replication.tcp.client import ReplicationDataHandler
from synapse.replication.tcp.commands import ClearUserSyncsCommand
from synapse.replication.tcp.streams import (
    AccountDataStream,
    DeviceListsStream,
    GroupServerStream,
    PresenceStream,
    PushersStream,
    PushRulesStream,
    ReceiptsStream,
    TagAccountDataStream,
    ToDeviceStream,
)
from synapse.rest.admin import register_servlets_for_media_repo
from synapse.rest.client.v1 import events, login, room
from synapse.rest.client.v1.initial_sync import InitialSyncRestServlet
from synapse.rest.client.v1.profile import (
    ProfileAvatarURLRestServlet,
    ProfileDisplaynameRestServlet,
    ProfileRestServlet,
)
from synapse.rest.client.v1.push_rule import PushRuleRestServlet
from synapse.rest.client.v1.voip import VoipRestServlet
from synapse.rest.client.v2_alpha import (
    account_data,
    groups,
    read_marker,
    receipts,
    room_keys,
    sync,
    tags,
    user_directory,
)
from synapse.rest.client.v2_alpha._base import client_patterns
from synapse.rest.client.v2_alpha.account import ThreepidRestServlet
from synapse.rest.client.v2_alpha.account_data import (
    AccountDataServlet,
    RoomAccountDataServlet,
)
from synapse.rest.client.v2_alpha.devices import DevicesRestServlet
from synapse.rest.client.v2_alpha.keys import (
    KeyChangesServlet,
    KeyQueryServlet,
    OneTimeKeyServlet,
)
from synapse.rest.client.v2_alpha.register import RegisterRestServlet
from synapse.rest.client.v2_alpha.sendtodevice import SendToDeviceRestServlet
from synapse.rest.client.versions import VersionsRestServlet
from synapse.rest.health import HealthResource
from synapse.rest.key.v2 import KeyApiV2Resource
from synapse.rest.synapse.client import build_synapse_client_resource_tree
from synapse.server import HomeServer, cache_in_self
from synapse.storage.databases.main.censor_events import CensorEventsStore
from synapse.storage.databases.main.client_ips import ClientIpWorkerStore
from synapse.storage.databases.main.e2e_room_keys import EndToEndRoomKeyStore
from synapse.storage.databases.main.media_repository import MediaRepositoryStore
from synapse.storage.databases.main.metrics import ServerMetricsStore
from synapse.storage.databases.main.monthly_active_users import (
    MonthlyActiveUsersWorkerStore,
)
from synapse.storage.databases.main.presence import UserPresenceState
from synapse.storage.databases.main.search import SearchWorkerStore
from synapse.storage.databases.main.stats import StatsStore
from synapse.storage.databases.main.transactions import TransactionWorkerStore
from synapse.storage.databases.main.ui_auth import UIAuthWorkerStore
from synapse.storage.databases.main.user_directory import UserDirectoryStore
from synapse.types import ReadReceipt
from synapse.util.async_helpers import Linearizer
from synapse.util.httpresourcetree import create_resource_tree
from synapse.util.manhole import manhole
from synapse.util.versionstring import get_version_string

logger = logging.getLogger("synapse.app.generic_worker")


class PresenceStatusStubServlet(RestServlet):
    """If presence is disabled this servlet can be used to stub out setting
    presence status.
    """

    PATTERNS = client_patterns("/presence/(?P<user_id>[^/]*)/status")

    def __init__(self, hs):
        super().__init__()
        self.auth = hs.get_auth()

    async def on_GET(self, request, user_id):
        await self.auth.get_user_by_req(request)
        return 200, {"presence": "offline"}

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
        super().__init__()
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

            # Proxy headers from the original request, such as the auth headers
            # (in case the access token is there) and the original IP /
            # User-Agent of the request.
            headers = {
                header: request.requestHeaders.getRawHeaders(header, [])
                for header in (b"Authorization", b"User-Agent")
            }
            # Add the previous hop the the X-Forwarded-For header.
            x_forwarded_for = request.requestHeaders.getRawHeaders(
                b"X-Forwarded-For", []
            )
            if isinstance(request.client, (address.IPv4Address, address.IPv6Address)):
                previous_host = request.client.host.encode("ascii")
                # If the header exists, add to the comma-separated list of the first
                # instance of the header. Otherwise, generate a new header.
                if x_forwarded_for:
                    x_forwarded_for = [
                        x_forwarded_for[0] + b", " + previous_host
                    ] + x_forwarded_for[1:]
                else:
                    x_forwarded_for = [previous_host]
            headers[b"X-Forwarded-For"] = x_forwarded_for

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


class _NullContextManager(ContextManager[None]):
    """A context manager which does nothing."""

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


UPDATE_SYNCING_USERS_MS = 10 * 1000


class GenericWorkerPresence(BasePresenceHandler):
    def __init__(self, hs):
        super().__init__(hs)
        self.hs = hs
        self.is_mine_id = hs.is_mine_id

        self._presence_enabled = hs.config.use_presence

        # The number of ongoing syncs on this process, by user id.
        # Empty if _presence_enabled is false.
        self._user_to_num_current_syncs = {}  # type: Dict[str, int]

        self.notifier = hs.get_notifier()
        self.instance_id = hs.get_instance_id()

        # user_id -> last_sync_ms. Lists the users that have stopped syncing
        # but we haven't notified the master of that yet
        self.users_going_offline = {}

        self._bump_active_client = ReplicationBumpPresenceActiveTime.make_client(hs)
        self._set_state_client = ReplicationPresenceSetState.make_client(hs)

        self._send_stop_syncing_loop = self.clock.looping_call(
            self.send_stop_syncing, UPDATE_SYNCING_USERS_MS
        )

        hs.get_reactor().addSystemEventTrigger(
            "before",
            "shutdown",
            run_as_background_process,
            "generic_presence.on_shutdown",
            self._on_shutdown,
        )

    def _on_shutdown(self):
        if self._presence_enabled:
            self.hs.get_tcp_replication().send_command(
                ClearUserSyncsCommand(self.instance_id)
            )

    def send_user_sync(self, user_id, is_syncing, last_sync_ms):
        if self._presence_enabled:
            self.hs.get_tcp_replication().send_user_sync(
                self.instance_id, user_id, is_syncing, last_sync_ms
            )

    def mark_as_coming_online(self, user_id):
        """A user has started syncing. Send a UserSync to the master, unless they
        had recently stopped syncing.

        Args:
            user_id (str)
        """
        going_offline = self.users_going_offline.pop(user_id, None)
        if not going_offline:
            # Safe to skip because we haven't yet told the master they were offline
            self.send_user_sync(user_id, True, self.clock.time_msec())

    def mark_as_going_offline(self, user_id):
        """A user has stopped syncing. We wait before notifying the master as
        its likely they'll come back soon. This allows us to avoid sending
        a stopped syncing immediately followed by a started syncing notification
        to the master

        Args:
            user_id (str)
        """
        self.users_going_offline[user_id] = self.clock.time_msec()

    def send_stop_syncing(self):
        """Check if there are any users who have stopped syncing a while ago
        and haven't come back yet. If there are poke the master about them.
        """
        now = self.clock.time_msec()
        for user_id, last_sync_ms in list(self.users_going_offline.items()):
            if now - last_sync_ms > UPDATE_SYNCING_USERS_MS:
                self.users_going_offline.pop(user_id, None)
                self.send_user_sync(user_id, False, last_sync_ms)

    async def user_syncing(
        self, user_id: str, affect_presence: bool
    ) -> ContextManager[None]:
        """Record that a user is syncing.

        Called by the sync and events servlets to record that a user has connected to
        this worker and is waiting for some events.
        """
        if not affect_presence or not self._presence_enabled:
            return _NullContextManager()

        curr_sync = self._user_to_num_current_syncs.get(user_id, 0)
        self._user_to_num_current_syncs[user_id] = curr_sync + 1

        # If we went from no in flight sync to some, notify replication
        if self._user_to_num_current_syncs[user_id] == 1:
            self.mark_as_coming_online(user_id)

        def _end():
            # We check that the user_id is in user_to_num_current_syncs because
            # user_to_num_current_syncs may have been cleared if we are
            # shutting down.
            if user_id in self._user_to_num_current_syncs:
                self._user_to_num_current_syncs[user_id] -= 1

                # If we went from one in flight sync to non, notify replication
                if self._user_to_num_current_syncs[user_id] == 0:
                    self.mark_as_going_offline(user_id)

        @contextlib.contextmanager
        def _user_syncing():
            try:
                yield
            finally:
                _end()

        return _user_syncing()

    async def notify_from_replication(self, states, stream_id):
        parties = await get_interested_parties(self.store, states)
        room_ids_to_states, users_to_states = parties

        self.notifier.on_new_event(
            "presence_key",
            stream_id,
            rooms=room_ids_to_states.keys(),
            users=users_to_states.keys(),
        )

    async def process_replication_rows(self, token, rows):
        states = [
            UserPresenceState(
                row.user_id,
                row.state,
                row.last_active_ts,
                row.last_federation_update_ts,
                row.last_user_sync_ts,
                row.status_msg,
                row.currently_active,
            )
            for row in rows
        ]

        for state in states:
            self.user_to_current_state[state.user_id] = state

        stream_id = token
        await self.notify_from_replication(states, stream_id)

    def get_currently_syncing_users_for_replication(self) -> Iterable[str]:
        return [
            user_id
            for user_id, count in self._user_to_num_current_syncs.items()
            if count > 0
        ]

    async def set_state(self, target_user, state, ignore_status_msg=False):
        """Set the presence state of the user."""
        presence = state["presence"]

        valid_presence = (
            PresenceState.ONLINE,
            PresenceState.UNAVAILABLE,
            PresenceState.OFFLINE,
        )
        if presence not in valid_presence:
            raise SynapseError(400, "Invalid presence state")

        user_id = target_user.to_string()

        # If presence is disabled, no-op
        if not self.hs.config.use_presence:
            return

        # Proxy request to master
        await self._set_state_client(
            user_id=user_id, state=state, ignore_status_msg=ignore_status_msg
        )

    async def bump_presence_active_time(self, user):
        """We've seen the user do something that indicates they're interacting
        with the app.
        """
        # If presence is disabled, no-op
        if not self.hs.config.use_presence:
            return

        # Proxy request to master
        user_id = user.to_string()
        await self._bump_active_client(user_id=user_id)


class GenericWorkerSlavedStore(
    # FIXME(#3714): We need to add UserDirectoryStore as we write directly
    # rather than going via the correct worker.
    UserDirectoryStore,
    StatsStore,
    UIAuthWorkerStore,
    EndToEndRoomKeyStore,
    SlavedDeviceInboxStore,
    SlavedDeviceStore,
    SlavedReceiptsStore,
    SlavedPushRuleStore,
    SlavedGroupServerStore,
    SlavedAccountDataStore,
    SlavedPusherStore,
    CensorEventsStore,
    ClientIpWorkerStore,
    SlavedEventStore,
    SlavedKeyStore,
    RoomStore,
    DirectoryStore,
    SlavedApplicationServiceStore,
    SlavedRegistrationStore,
    SlavedTransactionStore,
    SlavedProfileStore,
    SlavedClientIpStore,
    SlavedPresenceStore,
    SlavedFilteringStore,
    MonthlyActiveUsersWorkerStore,
    MediaRepositoryStore,
    ServerMetricsStore,
    SearchWorkerStore,
    TransactionWorkerStore,
    BaseSlavedStore,
):
    pass


class GenericWorkerServer(HomeServer):
    DATASTORE_CLASS = GenericWorkerSlavedStore

    def _listen_http(self, listener_config: ListenerConfig):
        port = listener_config.port
        bind_addresses = listener_config.bind_addresses

        assert listener_config.http_options is not None

        site_tag = listener_config.http_options.tag
        if site_tag is None:
            site_tag = port

        # We always include a health resource.
        resources = {"/health": HealthResource()}  # type: Dict[str, IResource]

        for res in listener_config.http_options.resources:
            for name in res.names:
                if name == "metrics":
                    resources[METRICS_PREFIX] = MetricsResource(RegistryProxy)
                elif name == "client":
                    resource = JsonResource(self, canonical_json=False)

                    RegisterRestServlet(self).register(resource)
                    login.register_servlets(self, resource)
                    ThreepidRestServlet(self).register(resource)
                    DevicesRestServlet(self).register(resource)
                    KeyQueryServlet(self).register(resource)
                    OneTimeKeyServlet(self).register(resource)
                    KeyChangesServlet(self).register(resource)
                    VoipRestServlet(self).register(resource)
                    PushRuleRestServlet(self).register(resource)
                    VersionsRestServlet(self).register(resource)

                    ProfileAvatarURLRestServlet(self).register(resource)
                    ProfileDisplaynameRestServlet(self).register(resource)
                    ProfileRestServlet(self).register(resource)
                    KeyUploadServlet(self).register(resource)
                    AccountDataServlet(self).register(resource)
                    RoomAccountDataServlet(self).register(resource)

                    sync.register_servlets(self, resource)
                    events.register_servlets(self, resource)
                    room.register_servlets(self, resource, True)
                    room.register_deprecated_servlets(self, resource)
                    InitialSyncRestServlet(self).register(resource)
                    room_keys.register_servlets(self, resource)
                    tags.register_servlets(self, resource)
                    account_data.register_servlets(self, resource)
                    receipts.register_servlets(self, resource)
                    read_marker.register_servlets(self, resource)

                    SendToDeviceRestServlet(self).register(resource)

                    user_directory.register_servlets(self, resource)

                    # If presence is disabled, use the stub servlet that does
                    # not allow sending presence
                    if not self.config.use_presence:
                        PresenceStatusStubServlet(self).register(resource)

                    groups.register_servlets(self, resource)

                    resources.update({CLIENT_API_PREFIX: resource})

                    resources.update(build_synapse_client_resource_tree(self))
                elif name == "federation":
                    resources.update({FEDERATION_PREFIX: TransportLayerServer(self)})
                elif name == "media":
                    if self.config.can_load_media_repo:
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
                    else:
                        logger.warning(
                            "A 'media' listener is configured but the media"
                            " repository is disabled. Ignoring."
                        )

                if name == "openid" and "federation" not in res.names:
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

                if name == "replication":
                    resources[REPLICATION_PREFIX] = ReplicationRestResource(self)

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
            ),
            reactor=self.get_reactor(),
        )

        logger.info("Synapse worker now listening on port %d", port)

    def start_listening(self, listeners: Iterable[ListenerConfig]):
        for listener in listeners:
            if listener.type == "http":
                self._listen_http(listener)
            elif listener.type == "manhole":
                _base.listen_tcp(
                    listener.bind_addresses,
                    listener.port,
                    manhole(
                        username="matrix", password="rabbithole", globals={"hs": self}
                    ),
                )
            elif listener.type == "metrics":
                if not self.get_config().enable_metrics:
                    logger.warning(
                        (
                            "Metrics listener configured, but "
                            "enable_metrics is not True!"
                        )
                    )
                else:
                    _base.listen_metrics(listener.bind_addresses, listener.port)
            else:
                logger.warning("Unsupported listener type: %s", listener.type)

        self.get_tcp_replication().start_replication(self)

    async def remove_pusher(self, app_id, push_key, user_id):
        self.get_tcp_replication().send_remove_pusher(app_id, push_key, user_id)

    @cache_in_self
    def get_replication_data_handler(self):
        return GenericWorkerReplicationHandler(self)

    @cache_in_self
    def get_presence_handler(self):
        return GenericWorkerPresence(self)


class GenericWorkerReplicationHandler(ReplicationDataHandler):
    def __init__(self, hs):
        super().__init__(hs)

        self.store = hs.get_datastore()
        self.presence_handler = hs.get_presence_handler()  # type: GenericWorkerPresence
        self.notifier = hs.get_notifier()

        self.notify_pushers = hs.config.start_pushers
        self.pusher_pool = hs.get_pusherpool()

        self.send_handler = None  # type: Optional[FederationSenderHandler]
        if hs.config.send_federation:
            self.send_handler = FederationSenderHandler(hs)

    async def on_rdata(self, stream_name, instance_name, token, rows):
        await super().on_rdata(stream_name, instance_name, token, rows)
        await self._process_and_notify(stream_name, instance_name, token, rows)

    async def _process_and_notify(self, stream_name, instance_name, token, rows):
        try:
            if self.send_handler:
                await self.send_handler.process_replication_rows(
                    stream_name, token, rows
                )

            if stream_name == PushRulesStream.NAME:
                self.notifier.on_new_event(
                    "push_rules_key", token, users=[row.user_id for row in rows]
                )
            elif stream_name in (AccountDataStream.NAME, TagAccountDataStream.NAME):
                self.notifier.on_new_event(
                    "account_data_key", token, users=[row.user_id for row in rows]
                )
            elif stream_name == ReceiptsStream.NAME:
                self.notifier.on_new_event(
                    "receipt_key", token, rooms=[row.room_id for row in rows]
                )
                await self.pusher_pool.on_new_receipts(
                    token, token, {row.room_id for row in rows}
                )
            elif stream_name == ToDeviceStream.NAME:
                entities = [row.entity for row in rows if row.entity.startswith("@")]
                if entities:
                    self.notifier.on_new_event("to_device_key", token, users=entities)
            elif stream_name == DeviceListsStream.NAME:
                all_room_ids = set()  # type: Set[str]
                for row in rows:
                    if row.entity.startswith("@"):
                        room_ids = await self.store.get_rooms_for_user(row.entity)
                        all_room_ids.update(room_ids)
                self.notifier.on_new_event("device_list_key", token, rooms=all_room_ids)
            elif stream_name == PresenceStream.NAME:
                await self.presence_handler.process_replication_rows(token, rows)
            elif stream_name == GroupServerStream.NAME:
                self.notifier.on_new_event(
                    "groups_key", token, users=[row.user_id for row in rows]
                )
            elif stream_name == PushersStream.NAME:
                for row in rows:
                    if row.deleted:
                        self.stop_pusher(row.user_id, row.app_id, row.pushkey)
                    else:
                        await self.start_pusher(row.user_id, row.app_id, row.pushkey)
        except Exception:
            logger.exception("Error processing replication")

    async def on_position(self, stream_name: str, instance_name: str, token: int):
        await super().on_position(stream_name, instance_name, token)
        # Also call on_rdata to ensure that stream positions are properly reset.
        await self.on_rdata(stream_name, instance_name, token, [])

    def stop_pusher(self, user_id, app_id, pushkey):
        if not self.notify_pushers:
            return

        key = "%s:%s" % (app_id, pushkey)
        pushers_for_user = self.pusher_pool.pushers.get(user_id, {})
        pusher = pushers_for_user.pop(key, None)
        if pusher is None:
            return
        logger.info("Stopping pusher %r / %r", user_id, key)
        pusher.on_stop()

    async def start_pusher(self, user_id, app_id, pushkey):
        if not self.notify_pushers:
            return

        key = "%s:%s" % (app_id, pushkey)
        logger.info("Starting pusher %r / %r", user_id, key)
        return await self.pusher_pool.start_pusher_by_id(app_id, pushkey, user_id)

    def on_remote_server_up(self, server: str):
        """Called when get a new REMOTE_SERVER_UP command."""

        # Let's wake up the transaction queue for the server in case we have
        # pending stuff to send to it.
        if self.send_handler:
            self.send_handler.wake_destination(server)


class FederationSenderHandler:
    """Processes the fedration replication stream

    This class is only instantiate on the worker responsible for sending outbound
    federation transactions. It receives rows from the replication stream and forwards
    the appropriate entries to the FederationSender class.
    """

    def __init__(self, hs: GenericWorkerServer):
        self.store = hs.get_datastore()
        self._is_mine_id = hs.is_mine_id
        self.federation_sender = hs.get_federation_sender()
        self._hs = hs

        # Stores the latest position in the federation stream we've gotten up
        # to. This is always set before we use it.
        self.federation_position = None

        self._fed_position_linearizer = Linearizer(name="_fed_position_linearizer")

    def on_start(self):
        # There may be some events that are persisted but haven't been sent,
        # so send them now.
        self.federation_sender.notify_new_events(
            self.store.get_room_max_stream_ordering()
        )

    def wake_destination(self, server: str):
        self.federation_sender.wake_destination(server)

    async def process_replication_rows(self, stream_name, token, rows):
        # The federation stream contains things that we want to send out, e.g.
        # presence, typing, etc.
        if stream_name == "federation":
            send_queue.process_rows_for_federation(self.federation_sender, rows)
            await self.update_token(token)

        # ... and when new receipts happen
        elif stream_name == ReceiptsStream.NAME:
            await self._on_new_receipts(rows)

        # ... as well as device updates and messages
        elif stream_name == DeviceListsStream.NAME:
            # The entities are either user IDs (starting with '@') whose devices
            # have changed, or remote servers that we need to tell about
            # changes.
            hosts = {row.entity for row in rows if not row.entity.startswith("@")}
            for host in hosts:
                self.federation_sender.send_device_messages(host)

        elif stream_name == ToDeviceStream.NAME:
            # The to_device stream includes stuff to be pushed to both local
            # clients and remote servers, so we ignore entities that start with
            # '@' (since they'll be local users rather than destinations).
            hosts = {row.entity for row in rows if not row.entity.startswith("@")}
            for host in hosts:
                self.federation_sender.send_device_messages(host)

    async def _on_new_receipts(self, rows):
        """
        Args:
            rows (Iterable[synapse.replication.tcp.streams.ReceiptsStream.ReceiptsStreamRow]):
                new receipts to be processed
        """
        for receipt in rows:
            # we only want to send on receipts for our own users
            if not self._is_mine_id(receipt.user_id):
                continue
            receipt_info = ReadReceipt(
                receipt.room_id,
                receipt.receipt_type,
                receipt.user_id,
                [receipt.event_id],
                receipt.data,
            )
            await self.federation_sender.send_read_receipt(receipt_info)

    async def update_token(self, token):
        """Update the record of where we have processed to in the federation stream.

        Called after we have processed a an update received over replication. Sends
        a FEDERATION_ACK back to the master, and stores the token that we have processed
         in `federation_stream_position` so that we can restart where we left off.
        """
        self.federation_position = token

        # We save and send the ACK to master asynchronously, so we don't block
        # processing on persistence. We don't need to do this operation for
        # every single RDATA we receive, we just need to do it periodically.

        if self._fed_position_linearizer.is_queued(None):
            # There is already a task queued up to save and send the token, so
            # no need to queue up another task.
            return

        run_as_background_process("_save_and_send_ack", self._save_and_send_ack)

    async def _save_and_send_ack(self):
        """Save the current federation position in the database and send an ACK
        to master with where we're up to.
        """
        try:
            # We linearize here to ensure we don't have races updating the token
            #
            # XXX this appears to be redundant, since the ReplicationCommandHandler
            # has a linearizer which ensures that we only process one line of
            # replication data at a time. Should we remove it, or is it doing useful
            # service for robustness? Or could we replace it with an assertion that
            # we're not being re-entered?

            with (await self._fed_position_linearizer.queue(None)):
                # We persist and ack the same position, so we take a copy of it
                # here as otherwise it can get modified from underneath us.
                current_position = self.federation_position

                await self.store.update_federation_out_pos(
                    "federation", current_position
                )

                # We ACK this token over replication so that the master can drop
                # its in memory queues
                self._hs.get_tcp_replication().send_federation_ack(current_position)
        except Exception:
            logger.exception("Error updating federation stream position")


def start(config_options):
    try:
        config = HomeServerConfig.load_config("Synapse worker", config_options)
    except ConfigError as e:
        sys.stderr.write("\n" + str(e) + "\n")
        sys.exit(1)

    # For backwards compatibility let any of the old app names.
    assert config.worker_app in (
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

    if config.worker_app == "synapse.app.appservice":
        if config.appservice.notify_appservices:
            sys.stderr.write(
                "\nThe appservices must be disabled in the main synapse process"
                "\nbefore they can be run in a separate worker."
                "\nPlease add ``notify_appservices: false`` to the main config"
                "\n"
            )
            sys.exit(1)

        # Force the appservice to start since they will be disabled in the main config
        config.appservice.notify_appservices = True
    else:
        # For other worker types we force this to off.
        config.appservice.notify_appservices = False

    if config.worker_app == "synapse.app.pusher":
        if config.server.start_pushers:
            sys.stderr.write(
                "\nThe pushers must be disabled in the main synapse process"
                "\nbefore they can be run in a separate worker."
                "\nPlease add ``start_pushers: false`` to the main config"
                "\n"
            )
            sys.exit(1)

        # Force the pushers to start since they will be disabled in the main config
        config.server.start_pushers = True
    else:
        # For other worker types we force this to off.
        config.server.start_pushers = False

    if config.worker_app == "synapse.app.user_dir":
        if config.server.update_user_directory:
            sys.stderr.write(
                "\nThe update_user_directory must be disabled in the main synapse process"
                "\nbefore they can be run in a separate worker."
                "\nPlease add ``update_user_directory: false`` to the main config"
                "\n"
            )
            sys.exit(1)

        # Force the pushers to start since they will be disabled in the main config
        config.server.update_user_directory = True
    else:
        # For other worker types we force this to off.
        config.server.update_user_directory = False

    if config.worker_app == "synapse.app.federation_sender":
        if config.worker.send_federation:
            sys.stderr.write(
                "\nThe send_federation must be disabled in the main synapse process"
                "\nbefore they can be run in a separate worker."
                "\nPlease add ``send_federation: false`` to the main config"
                "\n"
            )
            sys.exit(1)

        # Force the pushers to start since they will be disabled in the main config
        config.worker.send_federation = True
    else:
        # For other worker types we force this to off.
        config.worker.send_federation = False

    synapse.events.USE_FROZEN_DICTS = config.use_frozen_dicts

    hs = GenericWorkerServer(
        config.server_name,
        config=config,
        version_string="Synapse/" + get_version_string(synapse),
    )

    setup_logging(hs, config, use_worker_options=True)

    hs.setup()

    # Ensure the replication streamer is always started in case we write to any
    # streams. Will no-op if no streams can be written to by this worker.
    hs.get_replication_streamer()

    register_start(_base.start, hs, config.worker_listeners)

    _base.start_worker_reactor("synapse-generic-worker", config)


if __name__ == "__main__":
    with LoggingContext("main"):
        start(sys.argv[1:])
