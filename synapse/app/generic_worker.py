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

from twisted.internet import defer, reactor
from twisted.web.resource import NoResource

import synapse
import synapse.events
from synapse.api.constants import EventTypes
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
from synapse.federation import send_queue
from synapse.federation.transport.server import TransportLayerServer
from synapse.handlers.presence import PresenceHandler, get_interested_parties
from synapse.http.server import JsonResource
from synapse.http.servlet import RestServlet, parse_json_object_from_request
from synapse.http.site import SynapseSite
from synapse.logging.context import LoggingContext, run_in_background
from synapse.metrics import METRICS_PREFIX, MetricsResource, RegistryProxy
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.replication.slave.storage._base import BaseSlavedStore, __func__
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
from synapse.replication.tcp.client import ReplicationClientHandler
from synapse.replication.tcp.streams._base import (
    DeviceListsStream,
    ReceiptsStream,
    ToDeviceStream,
)
from synapse.replication.tcp.streams.events import EventsStreamEventRow, EventsStreamRow
from synapse.rest.admin import register_servlets_for_media_repo
from synapse.rest.client.v1 import events
from synapse.rest.client.v1.initial_sync import InitialSyncRestServlet
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
    RoomInitialSyncRestServlet,
    RoomMemberListRestServlet,
    RoomMembershipRestServlet,
    RoomMessageListRestServlet,
    RoomSendEventRestServlet,
    RoomStateEventRestServlet,
    RoomStateRestServlet,
)
from synapse.rest.client.v1.voip import VoipRestServlet
from synapse.rest.client.v2_alpha import groups, sync, user_directory
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
from synapse.storage.data_stores.main.presence import UserPresenceState
from synapse.storage.data_stores.main.user_directory import UserDirectoryStore
from synapse.types import ReadReceipt
from synapse.util.async_helpers import Linearizer
from synapse.util.httpresourcetree import create_resource_tree
from synapse.util.manhole import manhole
from synapse.util.stringutils import random_string
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


UPDATE_SYNCING_USERS_MS = 10 * 1000


class GenericWorkerPresence(object):
    def __init__(self, hs):
        self.hs = hs
        self.is_mine_id = hs.is_mine_id
        self.http_client = hs.get_simple_http_client()
        self.store = hs.get_datastore()
        self.user_to_num_current_syncs = {}
        self.clock = hs.get_clock()
        self.notifier = hs.get_notifier()

        active_presence = self.store.take_presence_startup_info()
        self.user_to_current_state = {state.user_id: state for state in active_presence}

        # user_id -> last_sync_ms. Lists the users that have stopped syncing
        # but we haven't notified the master of that yet
        self.users_going_offline = {}

        self._send_stop_syncing_loop = self.clock.looping_call(
            self.send_stop_syncing, UPDATE_SYNCING_USERS_MS
        )

        self.process_id = random_string(16)
        logger.info("Presence process_id is %r", self.process_id)

    def send_user_sync(self, user_id, is_syncing, last_sync_ms):
        if self.hs.config.use_presence:
            self.hs.get_tcp_replication().send_user_sync(
                user_id, is_syncing, last_sync_ms
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

    def set_state(self, user, state, ignore_status_msg=False):
        # TODO Hows this supposed to work?
        return defer.succeed(None)

    get_states = __func__(PresenceHandler.get_states)
    get_state = __func__(PresenceHandler.get_state)
    current_state_for_users = __func__(PresenceHandler.current_state_for_users)

    def user_syncing(self, user_id, affect_presence):
        if affect_presence:
            curr_sync = self.user_to_num_current_syncs.get(user_id, 0)
            self.user_to_num_current_syncs[user_id] = curr_sync + 1

            # If we went from no in flight sync to some, notify replication
            if self.user_to_num_current_syncs[user_id] == 1:
                self.mark_as_coming_online(user_id)

        def _end():
            # We check that the user_id is in user_to_num_current_syncs because
            # user_to_num_current_syncs may have been cleared if we are
            # shutting down.
            if affect_presence and user_id in self.user_to_num_current_syncs:
                self.user_to_num_current_syncs[user_id] -= 1

                # If we went from one in flight sync to non, notify replication
                if self.user_to_num_current_syncs[user_id] == 0:
                    self.mark_as_going_offline(user_id)

        @contextlib.contextmanager
        def _user_syncing():
            try:
                yield
            finally:
                _end()

        return defer.succeed(_user_syncing())

    @defer.inlineCallbacks
    def notify_from_replication(self, states, stream_id):
        parties = yield get_interested_parties(self.store, states)
        room_ids_to_states, users_to_states = parties

        self.notifier.on_new_event(
            "presence_key",
            stream_id,
            rooms=room_ids_to_states.keys(),
            users=users_to_states.keys(),
        )

    @defer.inlineCallbacks
    def process_replication_rows(self, token, rows):
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
        yield self.notify_from_replication(states, stream_id)

    def get_currently_syncing_users(self):
        if self.hs.config.use_presence:
            return [
                user_id
                for user_id, count in self.user_to_num_current_syncs.items()
                if count > 0
            ]
        else:
            return set()


class GenericWorkerTyping(object):
    def __init__(self, hs):
        self._latest_room_serial = 0
        self._reset()

    def _reset(self):
        """
        Reset the typing handler's data caches.
        """
        # map room IDs to serial numbers
        self._room_serials = {}
        # map room IDs to sets of users currently typing
        self._room_typing = {}

    def stream_positions(self):
        # We must update this typing token from the response of the previous
        # sync. In particular, the stream id may "reset" back to zero/a low
        # value which we *must* use for the next replication request.
        return {"typing": self._latest_room_serial}

    def process_replication_rows(self, token, rows):
        if self._latest_room_serial > token:
            # The master has gone backwards. To prevent inconsistent data, just
            # clear everything.
            self._reset()

        # Set the latest serial token to whatever the server gave us.
        self._latest_room_serial = token

        for row in rows:
            self._room_serials[row.room_id] = token
            self._room_typing[row.room_id] = row.user_ids


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
    SlavedPresenceStore,
    SlavedFilteringStore,
    MonthlyActiveUsersWorkerStore,
    MediaRepositoryStore,
    BaseSlavedStore,
):
    def __init__(self, database, db_conn, hs):
        super(GenericWorkerSlavedStore, self).__init__(database, db_conn, hs)

        # We pull out the current federation stream position now so that we
        # always have a known value for the federation position in memory so
        # that we don't have to bounce via a deferred once when we start the
        # replication streams.
        self.federation_out_pos_startup = self._get_federation_out_pos(db_conn)

    def _get_federation_out_pos(self, db_conn):
        sql = "SELECT stream_id FROM federation_stream_position WHERE type = ?"
        sql = self.database_engine.convert_param_style(sql)

        txn = db_conn.cursor()
        txn.execute(sql, ("federation",))
        rows = txn.fetchall()
        txn.close()

        return rows[0][0] if rows else -1


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

                    sync.register_servlets(self, resource)
                    events.register_servlets(self, resource)
                    InitialSyncRestServlet(self).register(resource)
                    RoomInitialSyncRestServlet(self).register(resource)

                    user_directory.register_servlets(self, resource)

                    # If presence is disabled, use the stub servlet that does
                    # not allow sending presence
                    if not self.config.use_presence:
                        PresenceStatusStubServlet(self).register(resource)

                    groups.register_servlets(self, resource)

                    resources.update({CLIENT_API_PREFIX: resource})
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

    def remove_pusher(self, app_id, push_key, user_id):
        self.get_tcp_replication().send_remove_pusher(app_id, push_key, user_id)

    def build_tcp_replication(self):
        return GenericWorkerReplicationHandler(self)

    def build_presence_handler(self):
        return GenericWorkerPresence(self)

    def build_typing_handler(self):
        return GenericWorkerTyping(self)


class GenericWorkerReplicationHandler(ReplicationClientHandler):
    def __init__(self, hs):
        super(GenericWorkerReplicationHandler, self).__init__(hs.get_datastore())

        self.store = hs.get_datastore()
        self.typing_handler = hs.get_typing_handler()
        # NB this is a SynchrotronPresence, not a normal PresenceHandler
        self.presence_handler = hs.get_presence_handler()
        self.notifier = hs.get_notifier()

        self.notify_pushers = hs.config.start_pushers
        self.pusher_pool = hs.get_pusherpool()

        if hs.config.send_federation:
            self.send_handler = FederationSenderHandler(hs, self)
        else:
            self.send_handler = None

    async def on_rdata(self, stream_name, token, rows):
        await super(GenericWorkerReplicationHandler, self).on_rdata(
            stream_name, token, rows
        )
        run_in_background(self.process_and_notify, stream_name, token, rows)

    def get_streams_to_replicate(self):
        args = super(GenericWorkerReplicationHandler, self).get_streams_to_replicate()
        args.update(self.typing_handler.stream_positions())
        if self.send_handler:
            args.update(self.send_handler.stream_positions())
        return args

    def get_currently_syncing_users(self):
        return self.presence_handler.get_currently_syncing_users()

    async def process_and_notify(self, stream_name, token, rows):
        try:
            if self.send_handler:
                self.send_handler.process_replication_rows(stream_name, token, rows)

            if stream_name == "events":
                # We shouldn't get multiple rows per token for events stream, so
                # we don't need to optimise this for multiple rows.
                for row in rows:
                    if row.type != EventsStreamEventRow.TypeId:
                        continue
                    assert isinstance(row, EventsStreamRow)

                    event = await self.store.get_event(
                        row.data.event_id, allow_rejected=True
                    )
                    if event.rejected_reason:
                        continue

                    extra_users = ()
                    if event.type == EventTypes.Member:
                        extra_users = (event.state_key,)
                    max_token = self.store.get_room_max_stream_ordering()
                    self.notifier.on_new_room_event(
                        event, token, max_token, extra_users
                    )

                await self.pusher_pool.on_new_notifications(token, token)
            elif stream_name == "push_rules":
                self.notifier.on_new_event(
                    "push_rules_key", token, users=[row.user_id for row in rows]
                )
            elif stream_name in ("account_data", "tag_account_data"):
                self.notifier.on_new_event(
                    "account_data_key", token, users=[row.user_id for row in rows]
                )
            elif stream_name == "receipts":
                self.notifier.on_new_event(
                    "receipt_key", token, rooms=[row.room_id for row in rows]
                )
                await self.pusher_pool.on_new_receipts(
                    token, token, {row.room_id for row in rows}
                )
            elif stream_name == "typing":
                self.typing_handler.process_replication_rows(token, rows)
                self.notifier.on_new_event(
                    "typing_key", token, rooms=[row.room_id for row in rows]
                )
            elif stream_name == "to_device":
                entities = [row.entity for row in rows if row.entity.startswith("@")]
                if entities:
                    self.notifier.on_new_event("to_device_key", token, users=entities)
            elif stream_name == "device_lists":
                all_room_ids = set()
                for row in rows:
                    room_ids = await self.store.get_rooms_for_user(row.user_id)
                    all_room_ids.update(room_ids)
                self.notifier.on_new_event("device_list_key", token, rooms=all_room_ids)
            elif stream_name == "presence":
                await self.presence_handler.process_replication_rows(token, rows)
            elif stream_name == "receipts":
                self.notifier.on_new_event(
                    "groups_key", token, users=[row.user_id for row in rows]
                )
            elif stream_name == "pushers":
                for row in rows:
                    if row.deleted:
                        self.stop_pusher(row.user_id, row.app_id, row.pushkey)
                    else:
                        await self.start_pusher(row.user_id, row.app_id, row.pushkey)
        except Exception:
            logger.exception("Error processing replication")

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


class FederationSenderHandler(object):
    """Processes the replication stream and forwards the appropriate entries
    to the federation sender.
    """

    def __init__(self, hs: GenericWorkerServer, replication_client):
        self.store = hs.get_datastore()
        self._is_mine_id = hs.is_mine_id
        self.federation_sender = hs.get_federation_sender()
        self.replication_client = replication_client

        self.federation_position = self.store.federation_out_pos_startup
        self._fed_position_linearizer = Linearizer(name="_fed_position_linearizer")

        self._last_ack = self.federation_position

        self._room_serials = {}
        self._room_typing = {}

    def on_start(self):
        # There may be some events that are persisted but haven't been sent,
        # so send them now.
        self.federation_sender.notify_new_events(
            self.store.get_room_max_stream_ordering()
        )

    def wake_destination(self, server: str):
        self.federation_sender.wake_destination(server)

    def stream_positions(self):
        return {"federation": self.federation_position}

    def process_replication_rows(self, stream_name, token, rows):
        # The federation stream contains things that we want to send out, e.g.
        # presence, typing, etc.
        if stream_name == "federation":
            send_queue.process_rows_for_federation(self.federation_sender, rows)
            run_in_background(self.update_token, token)

        # We also need to poke the federation sender when new events happen
        elif stream_name == "events":
            self.federation_sender.notify_new_events(token)

        # ... and when new receipts happen
        elif stream_name == ReceiptsStream.NAME:
            run_as_background_process(
                "process_receipts_for_federation", self._on_new_receipts, rows
            )

        # ... as well as device updates and messages
        elif stream_name == DeviceListsStream.NAME:
            hosts = {row.destination for row in rows}
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
            rows (iterable[synapse.replication.tcp.streams.ReceiptsStreamRow]):
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
        try:
            self.federation_position = token

            # We linearize here to ensure we don't have races updating the token
            with (await self._fed_position_linearizer.queue(None)):
                if self._last_ack < self.federation_position:
                    await self.store.update_federation_out_pos(
                        "federation", self.federation_position
                    )

                    # We ACK this token over replication so that the master can drop
                    # its in memory queues
                    self.replication_client.send_federation_ack(
                        self.federation_position
                    )
                    self._last_ack = self.federation_position
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
        if config.notify_appservices:
            sys.stderr.write(
                "\nThe appservices must be disabled in the main synapse process"
                "\nbefore they can be run in a separate worker."
                "\nPlease add ``notify_appservices: false`` to the main config"
                "\n"
            )
            sys.exit(1)

        # Force the appservice to start since they will be disabled in the main config
        config.notify_appservices = True

    if config.worker_app == "synapse.app.pusher":
        if config.start_pushers:
            sys.stderr.write(
                "\nThe pushers must be disabled in the main synapse process"
                "\nbefore they can be run in a separate worker."
                "\nPlease add ``start_pushers: false`` to the main config"
                "\n"
            )
            sys.exit(1)

        # Force the pushers to start since they will be disabled in the main config
        config.start_pushers = True

    if config.worker_app == "synapse.app.user_dir":
        if config.update_user_directory:
            sys.stderr.write(
                "\nThe update_user_directory must be disabled in the main synapse process"
                "\nbefore they can be run in a separate worker."
                "\nPlease add ``update_user_directory: false`` to the main config"
                "\n"
            )
            sys.exit(1)

        # Force the pushers to start since they will be disabled in the main config
        config.update_user_directory = True

    if config.worker_app == "synapse.app.federation_sender":
        if config.send_federation:
            sys.stderr.write(
                "\nThe send_federation must be disabled in the main synapse process"
                "\nbefore they can be run in a separate worker."
                "\nPlease add ``send_federation: false`` to the main config"
                "\n"
            )
            sys.exit(1)

        # Force the pushers to start since they will be disabled in the main config
        config.send_federation = True

    synapse.events.USE_FROZEN_DICTS = config.use_frozen_dicts

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
