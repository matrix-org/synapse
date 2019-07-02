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
import contextlib
import logging
import sys

from six import iteritems

from twisted.internet import defer, reactor
from twisted.web.resource import NoResource

import synapse
from synapse.api.constants import EventTypes
from synapse.app import _base
from synapse.config._base import ConfigError
from synapse.config.homeserver import HomeServerConfig
from synapse.config.logger import setup_logging
from synapse.handlers.presence import PresenceHandler, get_interested_parties
from synapse.http.server import JsonResource
from synapse.http.site import SynapseSite
from synapse.metrics import RegistryProxy
from synapse.metrics.resource import METRICS_PREFIX, MetricsResource
from synapse.replication.slave.storage._base import BaseSlavedStore, __func__
from synapse.replication.slave.storage.account_data import SlavedAccountDataStore
from synapse.replication.slave.storage.appservice import SlavedApplicationServiceStore
from synapse.replication.slave.storage.client_ips import SlavedClientIpStore
from synapse.replication.slave.storage.deviceinbox import SlavedDeviceInboxStore
from synapse.replication.slave.storage.devices import SlavedDeviceStore
from synapse.replication.slave.storage.events import SlavedEventStore
from synapse.replication.slave.storage.filtering import SlavedFilteringStore
from synapse.replication.slave.storage.groups import SlavedGroupServerStore
from synapse.replication.slave.storage.presence import SlavedPresenceStore
from synapse.replication.slave.storage.push_rule import SlavedPushRuleStore
from synapse.replication.slave.storage.receipts import SlavedReceiptsStore
from synapse.replication.slave.storage.registration import SlavedRegistrationStore
from synapse.replication.slave.storage.room import RoomStore
from synapse.replication.tcp.client import ReplicationClientHandler
from synapse.replication.tcp.streams.events import EventsStreamEventRow
from synapse.rest.client.v1 import events
from synapse.rest.client.v1.initial_sync import InitialSyncRestServlet
from synapse.rest.client.v1.room import RoomInitialSyncRestServlet
from synapse.rest.client.v2_alpha import sync
from synapse.server import HomeServer
from synapse.storage.engines import create_engine
from synapse.storage.presence import UserPresenceState
from synapse.util.httpresourcetree import create_resource_tree
from synapse.util.logcontext import LoggingContext, run_in_background
from synapse.util.manhole import manhole
from synapse.util.stringutils import random_string
from synapse.util.versionstring import get_version_string

logger = logging.getLogger("synapse.app.synchrotron")


class SynchrotronSlavedStore(
    SlavedReceiptsStore,
    SlavedAccountDataStore,
    SlavedApplicationServiceStore,
    SlavedRegistrationStore,
    SlavedFilteringStore,
    SlavedPresenceStore,
    SlavedGroupServerStore,
    SlavedDeviceInboxStore,
    SlavedDeviceStore,
    SlavedPushRuleStore,
    SlavedEventStore,
    SlavedClientIpStore,
    RoomStore,
    BaseSlavedStore,
):
    pass


UPDATE_SYNCING_USERS_MS = 10 * 1000


class SynchrotronPresence(object):
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
            self.send_stop_syncing, 10 * 1000
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
            if now - last_sync_ms > 10 * 1000:
                self.users_going_offline.pop(user_id, None)
                self.send_user_sync(user_id, False, last_sync_ms)

    def set_state(self, user, state, ignore_status_msg=False):
        # TODO Hows this supposed to work?
        pass

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
                for user_id, count in iteritems(self.user_to_num_current_syncs)
                if count > 0
            ]
        else:
            return set()


class SynchrotronTyping(object):
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


class SynchrotronApplicationService(object):
    def notify_interested_services(self, event):
        pass


class SynchrotronServer(HomeServer):
    DATASTORE_CLASS = SynchrotronSlavedStore

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
                    sync.register_servlets(self, resource)
                    events.register_servlets(self, resource)
                    InitialSyncRestServlet(self).register(resource)
                    RoomInitialSyncRestServlet(self).register(resource)
                    resources.update(
                        {
                            "/_matrix/client/r0": resource,
                            "/_matrix/client/unstable": resource,
                            "/_matrix/client/v2_alpha": resource,
                            "/_matrix/client/api/v1": resource,
                        }
                    )

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
        )

        logger.info("Synapse synchrotron now listening on port %d", port)

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
                    logger.warn(
                        (
                            "Metrics listener configured, but "
                            "enable_metrics is not True!"
                        )
                    )
                else:
                    _base.listen_metrics(listener["bind_addresses"], listener["port"])
            else:
                logger.warn("Unrecognized listener type: %s", listener["type"])

        self.get_tcp_replication().start_replication(self)

    def build_tcp_replication(self):
        return SyncReplicationHandler(self)

    def build_presence_handler(self):
        return SynchrotronPresence(self)

    def build_typing_handler(self):
        return SynchrotronTyping(self)


class SyncReplicationHandler(ReplicationClientHandler):
    def __init__(self, hs):
        super(SyncReplicationHandler, self).__init__(hs.get_datastore())

        self.store = hs.get_datastore()
        self.typing_handler = hs.get_typing_handler()
        # NB this is a SynchrotronPresence, not a normal PresenceHandler
        self.presence_handler = hs.get_presence_handler()
        self.notifier = hs.get_notifier()

    @defer.inlineCallbacks
    def on_rdata(self, stream_name, token, rows):
        yield super(SyncReplicationHandler, self).on_rdata(stream_name, token, rows)
        run_in_background(self.process_and_notify, stream_name, token, rows)

    def get_streams_to_replicate(self):
        args = super(SyncReplicationHandler, self).get_streams_to_replicate()
        args.update(self.typing_handler.stream_positions())
        return args

    def get_currently_syncing_users(self):
        return self.presence_handler.get_currently_syncing_users()

    @defer.inlineCallbacks
    def process_and_notify(self, stream_name, token, rows):
        try:
            if stream_name == "events":
                # We shouldn't get multiple rows per token for events stream, so
                # we don't need to optimise this for multiple rows.
                for row in rows:
                    if row.type != EventsStreamEventRow.TypeId:
                        continue
                    event = yield self.store.get_event(row.data.event_id)
                    extra_users = ()
                    if event.type == EventTypes.Member:
                        extra_users = (event.state_key,)
                    max_token = self.store.get_room_max_stream_ordering()
                    self.notifier.on_new_room_event(
                        event, token, max_token, extra_users
                    )
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
                    room_ids = yield self.store.get_rooms_for_user(row.user_id)
                    all_room_ids.update(room_ids)
                self.notifier.on_new_event("device_list_key", token, rooms=all_room_ids)
            elif stream_name == "presence":
                yield self.presence_handler.process_replication_rows(token, rows)
            elif stream_name == "receipts":
                self.notifier.on_new_event(
                    "groups_key", token, users=[row.user_id for row in rows]
                )
        except Exception:
            logger.exception("Error processing replication")


def start(config_options):
    try:
        config = HomeServerConfig.load_config("Synapse synchrotron", config_options)
    except ConfigError as e:
        sys.stderr.write("\n" + str(e) + "\n")
        sys.exit(1)

    assert config.worker_app == "synapse.app.synchrotron"

    setup_logging(config, use_worker_options=True)

    synapse.events.USE_FROZEN_DICTS = config.use_frozen_dicts

    database_engine = create_engine(config.database_config)

    ss = SynchrotronServer(
        config.server_name,
        db_config=config.database_config,
        config=config,
        version_string="Synapse/" + get_version_string(synapse),
        database_engine=database_engine,
        application_service_handler=SynchrotronApplicationService(),
    )

    ss.setup()
    reactor.callWhenRunning(_base.start, ss, config.worker_listeners)

    _base.start_worker_reactor("synapse-synchrotron", config)


if __name__ == "__main__":
    with LoggingContext("main"):
        start(sys.argv[1:])
