# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

"""This module is responsible for keeping track of presence status of local
and remote users.

The methods that define policy are:
    - PresenceHandler._update_states
    - PresenceHandler._handle_timeouts
    - should_notify
"""
import abc
import logging
from contextlib import contextmanager
from typing import (
    TYPE_CHECKING,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

from prometheus_client import Counter
from typing_extensions import ContextManager

import synapse.metrics
from synapse.api.constants import EventTypes, Membership, PresenceState
from synapse.api.errors import SynapseError
from synapse.api.presence import UserPresenceState
from synapse.events.presence_router import PresenceRouter
from synapse.logging.context import run_in_background
from synapse.logging.utils import log_function
from synapse.metrics import LaterGauge
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.state import StateHandler
from synapse.storage.databases.main import DataStore
from synapse.types import Collection, JsonDict, UserID, get_domain_from_id
from synapse.util.async_helpers import Linearizer
from synapse.util.caches.descriptors import _CacheContext, cached
from synapse.util.metrics import Measure
from synapse.util.wheel_timer import WheelTimer

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


notified_presence_counter = Counter("synapse_handler_presence_notified_presence", "")
federation_presence_out_counter = Counter(
    "synapse_handler_presence_federation_presence_out", ""
)
presence_updates_counter = Counter("synapse_handler_presence_presence_updates", "")
timers_fired_counter = Counter("synapse_handler_presence_timers_fired", "")
federation_presence_counter = Counter(
    "synapse_handler_presence_federation_presence", ""
)
bump_active_time_counter = Counter("synapse_handler_presence_bump_active_time", "")

get_updates_counter = Counter("synapse_handler_presence_get_updates", "", ["type"])

notify_reason_counter = Counter(
    "synapse_handler_presence_notify_reason", "", ["reason"]
)
state_transition_counter = Counter(
    "synapse_handler_presence_state_transition", "", ["from", "to"]
)


# If a user was last active in the last LAST_ACTIVE_GRANULARITY, consider them
# "currently_active"
LAST_ACTIVE_GRANULARITY = 60 * 1000

# How long to wait until a new /events or /sync request before assuming
# the client has gone.
SYNC_ONLINE_TIMEOUT = 30 * 1000

# How long to wait before marking the user as idle. Compared against last active
IDLE_TIMER = 5 * 60 * 1000

# How often we expect remote servers to resend us presence.
FEDERATION_TIMEOUT = 30 * 60 * 1000

# How often to resend presence to remote servers
FEDERATION_PING_INTERVAL = 25 * 60 * 1000

# How long we will wait before assuming that the syncs from an external process
# are dead.
EXTERNAL_PROCESS_EXPIRY = 5 * 60 * 1000

assert LAST_ACTIVE_GRANULARITY < IDLE_TIMER


class BasePresenceHandler(abc.ABC):
    """Parts of the PresenceHandler that are shared between workers and master"""

    def __init__(self, hs: "HomeServer"):
        self.clock = hs.get_clock()
        self.store = hs.get_datastore()

        self._busy_presence_enabled = hs.config.experimental.msc3026_enabled

        active_presence = self.store.take_presence_startup_info()
        self.user_to_current_state = {state.user_id: state for state in active_presence}

    @abc.abstractmethod
    async def user_syncing(
        self, user_id: str, affect_presence: bool
    ) -> ContextManager[None]:
        """Returns a context manager that should surround any stream requests
        from the user.

        This allows us to keep track of who is currently streaming and who isn't
        without having to have timers outside of this module to avoid flickering
        when users disconnect/reconnect.

        Args:
            user_id: the user that is starting a sync
            affect_presence: If false this function will be a no-op.
                Useful for streams that are not associated with an actual
                client that is being used by a user.
        """

    @abc.abstractmethod
    def get_currently_syncing_users_for_replication(self) -> Iterable[str]:
        """Get an iterable of syncing users on this worker, to send to the presence handler

        This is called when a replication connection is established. It should return
        a list of user ids, which are then sent as USER_SYNC commands to inform the
        process handling presence about those users.

        Returns:
            An iterable of user_id strings.
        """

    async def get_state(self, target_user: UserID) -> UserPresenceState:
        results = await self.get_states([target_user.to_string()])
        return results[0]

    async def get_states(
        self, target_user_ids: Iterable[str]
    ) -> List[UserPresenceState]:
        """Get the presence state for users."""

        updates_d = await self.current_state_for_users(target_user_ids)
        updates = list(updates_d.values())

        for user_id in set(target_user_ids) - {u.user_id for u in updates}:
            updates.append(UserPresenceState.default(user_id))

        return updates

    async def current_state_for_users(
        self, user_ids: Iterable[str]
    ) -> Dict[str, UserPresenceState]:
        """Get the current presence state for multiple users.

        Returns:
            dict: `user_id` -> `UserPresenceState`
        """
        states = {
            user_id: self.user_to_current_state.get(user_id, None)
            for user_id in user_ids
        }

        missing = [user_id for user_id, state in states.items() if not state]
        if missing:
            # There are things not in our in memory cache. Lets pull them out of
            # the database.
            res = await self.store.get_presence_for_users(missing)
            states.update(res)

            missing = [user_id for user_id, state in states.items() if not state]
            if missing:
                new = {
                    user_id: UserPresenceState.default(user_id) for user_id in missing
                }
                states.update(new)
                self.user_to_current_state.update(new)

        return states

    @abc.abstractmethod
    async def set_state(
        self, target_user: UserID, state: JsonDict, ignore_status_msg: bool = False
    ) -> None:
        """Set the presence state of the user. """

    @abc.abstractmethod
    async def bump_presence_active_time(self, user: UserID):
        """We've seen the user do something that indicates they're interacting
        with the app.
        """


class PresenceHandler(BasePresenceHandler):
    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        self.hs = hs
        self.is_mine_id = hs.is_mine_id
        self.server_name = hs.hostname
        self.wheel_timer = WheelTimer()
        self.notifier = hs.get_notifier()
        self.federation = hs.get_federation_sender()
        self.state = hs.get_state_handler()
        self.presence_router = hs.get_presence_router()
        self._presence_enabled = hs.config.use_presence

        federation_registry = hs.get_federation_registry()

        federation_registry.register_edu_handler("m.presence", self.incoming_presence)

        LaterGauge(
            "synapse_handlers_presence_user_to_current_state_size",
            "",
            [],
            lambda: len(self.user_to_current_state),
        )

        now = self.clock.time_msec()
        for state in self.user_to_current_state.values():
            self.wheel_timer.insert(
                now=now, obj=state.user_id, then=state.last_active_ts + IDLE_TIMER
            )
            self.wheel_timer.insert(
                now=now,
                obj=state.user_id,
                then=state.last_user_sync_ts + SYNC_ONLINE_TIMEOUT,
            )
            if self.is_mine_id(state.user_id):
                self.wheel_timer.insert(
                    now=now,
                    obj=state.user_id,
                    then=state.last_federation_update_ts + FEDERATION_PING_INTERVAL,
                )
            else:
                self.wheel_timer.insert(
                    now=now,
                    obj=state.user_id,
                    then=state.last_federation_update_ts + FEDERATION_TIMEOUT,
                )

        # Set of users who have presence in the `user_to_current_state` that
        # have not yet been persisted
        self.unpersisted_users_changes = set()  # type: Set[str]

        hs.get_reactor().addSystemEventTrigger(
            "before",
            "shutdown",
            run_as_background_process,
            "presence.on_shutdown",
            self._on_shutdown,
        )

        self._next_serial = 1

        # Keeps track of the number of *ongoing* syncs on this process. While
        # this is non zero a user will never go offline.
        self.user_to_num_current_syncs = {}  # type: Dict[str, int]

        # Keeps track of the number of *ongoing* syncs on other processes.
        # While any sync is ongoing on another process the user will never
        # go offline.
        # Each process has a unique identifier and an update frequency. If
        # no update is received from that process within the update period then
        # we assume that all the sync requests on that process have stopped.
        # Stored as a dict from process_id to set of user_id, and a dict of
        # process_id to millisecond timestamp last updated.
        self.external_process_to_current_syncs = {}  # type: Dict[int, Set[str]]
        self.external_process_last_updated_ms = {}  # type: Dict[int, int]

        self.external_sync_linearizer = Linearizer(name="external_sync_linearizer")

        if self._presence_enabled:
            # Start a LoopingCall in 30s that fires every 5s.
            # The initial delay is to allow disconnected clients a chance to
            # reconnect before we treat them as offline.
            def run_timeout_handler():
                return run_as_background_process(
                    "handle_presence_timeouts", self._handle_timeouts
                )

            self.clock.call_later(
                30, self.clock.looping_call, run_timeout_handler, 5000
            )

            def run_persister():
                return run_as_background_process(
                    "persist_presence_changes", self._persist_unpersisted_changes
                )

            self.clock.call_later(60, self.clock.looping_call, run_persister, 60 * 1000)

        LaterGauge(
            "synapse_handlers_presence_wheel_timer_size",
            "",
            [],
            lambda: len(self.wheel_timer),
        )

        # Used to handle sending of presence to newly joined users/servers
        if self._presence_enabled:
            self.notifier.add_replication_callback(self.notify_new_event)

        # Presence is best effort and quickly heals itself, so lets just always
        # stream from the current state when we restart.
        self._event_pos = self.store.get_current_events_token()
        self._event_processing = False

    async def _on_shutdown(self):
        """Gets called when shutting down. This lets us persist any updates that
        we haven't yet persisted, e.g. updates that only changes some internal
        timers. This allows changes to persist across startup without having to
        persist every single change.

        If this does not run it simply means that some of the timers will fire
        earlier than they should when synapse is restarted. This affect of this
        is some spurious presence changes that will self-correct.
        """
        # If the DB pool has already terminated, don't try updating
        if not self.store.db_pool.is_running():
            return

        logger.info(
            "Performing _on_shutdown. Persisting %d unpersisted changes",
            len(self.user_to_current_state),
        )

        if self.unpersisted_users_changes:

            await self.store.update_presence(
                [
                    self.user_to_current_state[user_id]
                    for user_id in self.unpersisted_users_changes
                ]
            )
        logger.info("Finished _on_shutdown")

    async def _persist_unpersisted_changes(self):
        """We periodically persist the unpersisted changes, as otherwise they
        may stack up and slow down shutdown times.
        """
        unpersisted = self.unpersisted_users_changes
        self.unpersisted_users_changes = set()

        if unpersisted:
            logger.info("Persisting %d unpersisted presence updates", len(unpersisted))
            await self.store.update_presence(
                [self.user_to_current_state[user_id] for user_id in unpersisted]
            )

    async def _update_states(self, new_states: Iterable[UserPresenceState]) -> None:
        """Updates presence of users. Sets the appropriate timeouts. Pokes
        the notifier and federation if and only if the changed presence state
        should be sent to clients/servers.

        Args:
            new_states: The new user presence state updates to process.
        """
        now = self.clock.time_msec()

        with Measure(self.clock, "presence_update_states"):

            # NOTE: We purposefully don't await between now and when we've
            # calculated what we want to do with the new states, to avoid races.

            to_notify = {}  # Changes we want to notify everyone about
            to_federation_ping = {}  # These need sending keep-alives

            # Only bother handling the last presence change for each user
            new_states_dict = {}
            for new_state in new_states:
                new_states_dict[new_state.user_id] = new_state
            new_states = new_states_dict.values()

            for new_state in new_states:
                user_id = new_state.user_id

                # Its fine to not hit the database here, as the only thing not in
                # the current state cache are OFFLINE states, where the only field
                # of interest is last_active which is safe enough to assume is 0
                # here.
                prev_state = self.user_to_current_state.get(
                    user_id, UserPresenceState.default(user_id)
                )

                new_state, should_notify, should_ping = handle_update(
                    prev_state,
                    new_state,
                    is_mine=self.is_mine_id(user_id),
                    wheel_timer=self.wheel_timer,
                    now=now,
                )

                self.user_to_current_state[user_id] = new_state

                if should_notify:
                    to_notify[user_id] = new_state
                elif should_ping:
                    to_federation_ping[user_id] = new_state

            # TODO: We should probably ensure there are no races hereafter

            presence_updates_counter.inc(len(new_states))

            if to_notify:
                notified_presence_counter.inc(len(to_notify))
                await self._persist_and_notify(list(to_notify.values()))

            self.unpersisted_users_changes |= {s.user_id for s in new_states}
            self.unpersisted_users_changes -= set(to_notify.keys())

            to_federation_ping = {
                user_id: state
                for user_id, state in to_federation_ping.items()
                if user_id not in to_notify
            }
            if to_federation_ping:
                federation_presence_out_counter.inc(len(to_federation_ping))

                self._push_to_remotes(to_federation_ping.values())

    async def _handle_timeouts(self):
        """Checks the presence of users that have timed out and updates as
        appropriate.
        """
        logger.debug("Handling presence timeouts")
        now = self.clock.time_msec()

        # Fetch the list of users that *may* have timed out. Things may have
        # changed since the timeout was set, so we won't necessarily have to
        # take any action.
        users_to_check = set(self.wheel_timer.fetch(now))

        # Check whether the lists of syncing processes from an external
        # process have expired.
        expired_process_ids = [
            process_id
            for process_id, last_update in self.external_process_last_updated_ms.items()
            if now - last_update > EXTERNAL_PROCESS_EXPIRY
        ]
        for process_id in expired_process_ids:
            # For each expired process drop tracking info and check the users
            # that were syncing on that process to see if they need to be timed
            # out.
            users_to_check.update(
                self.external_process_to_current_syncs.pop(process_id, ())
            )
            self.external_process_last_updated_ms.pop(process_id)

        states = [
            self.user_to_current_state.get(user_id, UserPresenceState.default(user_id))
            for user_id in users_to_check
        ]

        timers_fired_counter.inc(len(states))

        syncing_user_ids = {
            user_id
            for user_id, count in self.user_to_num_current_syncs.items()
            if count
        }
        for user_ids in self.external_process_to_current_syncs.values():
            syncing_user_ids.update(user_ids)

        changes = handle_timeouts(
            states,
            is_mine_fn=self.is_mine_id,
            syncing_user_ids=syncing_user_ids,
            now=now,
        )

        return await self._update_states(changes)

    async def bump_presence_active_time(self, user):
        """We've seen the user do something that indicates they're interacting
        with the app.
        """
        # If presence is disabled, no-op
        if not self.hs.config.use_presence:
            return

        user_id = user.to_string()

        bump_active_time_counter.inc()

        prev_state = await self.current_state_for_user(user_id)

        new_fields = {"last_active_ts": self.clock.time_msec()}
        if prev_state.state == PresenceState.UNAVAILABLE:
            new_fields["state"] = PresenceState.ONLINE

        await self._update_states([prev_state.copy_and_replace(**new_fields)])

    async def user_syncing(
        self, user_id: str, affect_presence: bool = True
    ) -> ContextManager[None]:
        """Returns a context manager that should surround any stream requests
        from the user.

        This allows us to keep track of who is currently streaming and who isn't
        without having to have timers outside of this module to avoid flickering
        when users disconnect/reconnect.

        Args:
            user_id (str)
            affect_presence (bool): If false this function will be a no-op.
                Useful for streams that are not associated with an actual
                client that is being used by a user.
        """
        # Override if it should affect the user's presence, if presence is
        # disabled.
        if not self.hs.config.use_presence:
            affect_presence = False

        if affect_presence:
            curr_sync = self.user_to_num_current_syncs.get(user_id, 0)
            self.user_to_num_current_syncs[user_id] = curr_sync + 1

            prev_state = await self.current_state_for_user(user_id)
            if prev_state.state == PresenceState.OFFLINE:
                # If they're currently offline then bring them online, otherwise
                # just update the last sync times.
                await self._update_states(
                    [
                        prev_state.copy_and_replace(
                            state=PresenceState.ONLINE,
                            last_active_ts=self.clock.time_msec(),
                            last_user_sync_ts=self.clock.time_msec(),
                        )
                    ]
                )
            else:
                await self._update_states(
                    [
                        prev_state.copy_and_replace(
                            last_user_sync_ts=self.clock.time_msec()
                        )
                    ]
                )

        async def _end():
            try:
                self.user_to_num_current_syncs[user_id] -= 1

                prev_state = await self.current_state_for_user(user_id)
                await self._update_states(
                    [
                        prev_state.copy_and_replace(
                            last_user_sync_ts=self.clock.time_msec()
                        )
                    ]
                )
            except Exception:
                logger.exception("Error updating presence after sync")

        @contextmanager
        def _user_syncing():
            try:
                yield
            finally:
                if affect_presence:
                    run_in_background(_end)

        return _user_syncing()

    def get_currently_syncing_users_for_replication(self) -> Iterable[str]:
        # since we are the process handling presence, there is nothing to do here.
        return []

    async def update_external_syncs_row(
        self, process_id, user_id, is_syncing, sync_time_msec
    ):
        """Update the syncing users for an external process as a delta.

        Args:
            process_id (str): An identifier for the process the users are
                syncing against. This allows synapse to process updates
                as user start and stop syncing against a given process.
            user_id (str): The user who has started or stopped syncing
            is_syncing (bool): Whether or not the user is now syncing
            sync_time_msec(int): Time in ms when the user was last syncing
        """
        with (await self.external_sync_linearizer.queue(process_id)):
            prev_state = await self.current_state_for_user(user_id)

            process_presence = self.external_process_to_current_syncs.setdefault(
                process_id, set()
            )

            updates = []
            if is_syncing and user_id not in process_presence:
                if prev_state.state == PresenceState.OFFLINE:
                    updates.append(
                        prev_state.copy_and_replace(
                            state=PresenceState.ONLINE,
                            last_active_ts=sync_time_msec,
                            last_user_sync_ts=sync_time_msec,
                        )
                    )
                else:
                    updates.append(
                        prev_state.copy_and_replace(last_user_sync_ts=sync_time_msec)
                    )
                process_presence.add(user_id)
            elif user_id in process_presence:
                updates.append(
                    prev_state.copy_and_replace(last_user_sync_ts=sync_time_msec)
                )

            if not is_syncing:
                process_presence.discard(user_id)

            if updates:
                await self._update_states(updates)

            self.external_process_last_updated_ms[process_id] = self.clock.time_msec()

    async def update_external_syncs_clear(self, process_id):
        """Marks all users that had been marked as syncing by a given process
        as offline.

        Used when the process has stopped/disappeared.
        """
        with (await self.external_sync_linearizer.queue(process_id)):
            process_presence = self.external_process_to_current_syncs.pop(
                process_id, set()
            )
            prev_states = await self.current_state_for_users(process_presence)
            time_now_ms = self.clock.time_msec()

            await self._update_states(
                [
                    prev_state.copy_and_replace(last_user_sync_ts=time_now_ms)
                    for prev_state in prev_states.values()
                ]
            )
            self.external_process_last_updated_ms.pop(process_id, None)

    async def current_state_for_user(self, user_id):
        """Get the current presence state for a user."""
        res = await self.current_state_for_users([user_id])
        return res[user_id]

    async def _persist_and_notify(self, states):
        """Persist states in the database, poke the notifier and send to
        interested remote servers
        """
        stream_id, max_token = await self.store.update_presence(states)

        parties = await get_interested_parties(self.store, self.presence_router, states)
        room_ids_to_states, users_to_states = parties

        self.notifier.on_new_event(
            "presence_key",
            stream_id,
            rooms=room_ids_to_states.keys(),
            users=[UserID.from_string(u) for u in users_to_states],
        )

        self._push_to_remotes(states)

    def _push_to_remotes(self, states):
        """Sends state updates to remote servers.

        Args:
            states (list(UserPresenceState))
        """
        self.federation.send_presence(states)

    async def incoming_presence(self, origin, content):
        """Called when we receive a `m.presence` EDU from a remote server."""
        if not self._presence_enabled:
            return

        now = self.clock.time_msec()
        updates = []
        for push in content.get("push", []):
            # A "push" contains a list of presence that we are probably interested
            # in.
            user_id = push.get("user_id", None)
            if not user_id:
                logger.info(
                    "Got presence update from %r with no 'user_id': %r", origin, push
                )
                continue

            if get_domain_from_id(user_id) != origin:
                logger.info(
                    "Got presence update from %r with bad 'user_id': %r",
                    origin,
                    user_id,
                )
                continue

            presence_state = push.get("presence", None)
            if not presence_state:
                logger.info(
                    "Got presence update from %r with no 'presence_state': %r",
                    origin,
                    push,
                )
                continue

            new_fields = {"state": presence_state, "last_federation_update_ts": now}

            last_active_ago = push.get("last_active_ago", None)
            if last_active_ago is not None:
                new_fields["last_active_ts"] = now - last_active_ago

            new_fields["status_msg"] = push.get("status_msg", None)
            new_fields["currently_active"] = push.get("currently_active", False)

            prev_state = await self.current_state_for_user(user_id)
            updates.append(prev_state.copy_and_replace(**new_fields))

        if updates:
            federation_presence_counter.inc(len(updates))
            await self._update_states(updates)

    async def set_state(self, target_user, state, ignore_status_msg=False):
        """Set the presence state of the user."""
        status_msg = state.get("status_msg", None)
        presence = state["presence"]

        valid_presence = (
            PresenceState.ONLINE,
            PresenceState.UNAVAILABLE,
            PresenceState.OFFLINE,
            PresenceState.BUSY,
        )

        if presence not in valid_presence or (
            presence == PresenceState.BUSY and not self._busy_presence_enabled
        ):
            raise SynapseError(400, "Invalid presence state")

        user_id = target_user.to_string()

        prev_state = await self.current_state_for_user(user_id)

        new_fields = {"state": presence}

        if not ignore_status_msg:
            msg = status_msg if presence != PresenceState.OFFLINE else None
            new_fields["status_msg"] = msg

        if presence == PresenceState.ONLINE or (
            presence == PresenceState.BUSY and self._busy_presence_enabled
        ):
            new_fields["last_active_ts"] = self.clock.time_msec()

        await self._update_states([prev_state.copy_and_replace(**new_fields)])

    async def is_visible(self, observed_user, observer_user):
        """Returns whether a user can see another user's presence."""
        observer_room_ids = await self.store.get_rooms_for_user(
            observer_user.to_string()
        )
        observed_room_ids = await self.store.get_rooms_for_user(
            observed_user.to_string()
        )

        if observer_room_ids & observed_room_ids:
            return True

        return False

    async def get_all_presence_updates(
        self, instance_name: str, last_id: int, current_id: int, limit: int
    ) -> Tuple[List[Tuple[int, list]], int, bool]:
        """
        Gets a list of presence update rows from between the given stream ids.
        Each row has:
        - stream_id(str)
        - user_id(str)
        - state(str)
        - last_active_ts(int)
        - last_federation_update_ts(int)
        - last_user_sync_ts(int)
        - status_msg(int)
        - currently_active(int)

        Args:
            instance_name: The writer we want to fetch updates from. Unused
                here since there is only ever one writer.
            last_id: The token to fetch updates from. Exclusive.
            current_id: The token to fetch updates up to. Inclusive.
            limit: The requested limit for the number of rows to return. The
                function may return more or fewer rows.

        Returns:
            A tuple consisting of: the updates, a token to use to fetch
            subsequent updates, and whether we returned fewer rows than exists
            between the requested tokens due to the limit.

            The token returned can be used in a subsequent call to this
            function to get further updates.

            The updates are a list of 2-tuples of stream ID and the row data
        """

        # TODO(markjh): replicate the unpersisted changes.
        # This could use the in-memory stores for recent changes.
        rows = await self.store.get_all_presence_updates(
            instance_name, last_id, current_id, limit
        )
        return rows

    def notify_new_event(self):
        """Called when new events have happened. Handles users and servers
        joining rooms and require being sent presence.
        """

        if self._event_processing:
            return

        async def _process_presence():
            assert not self._event_processing

            self._event_processing = True
            try:
                await self._unsafe_process()
            finally:
                self._event_processing = False

        run_as_background_process("presence.notify_new_event", _process_presence)

    async def _unsafe_process(self):
        # Loop round handling deltas until we're up to date
        while True:
            with Measure(self.clock, "presence_delta"):
                room_max_stream_ordering = self.store.get_room_max_stream_ordering()
                if self._event_pos == room_max_stream_ordering:
                    return

                logger.debug(
                    "Processing presence stats %s->%s",
                    self._event_pos,
                    room_max_stream_ordering,
                )
                max_pos, deltas = await self.store.get_current_state_deltas(
                    self._event_pos, room_max_stream_ordering
                )
                await self._handle_state_delta(deltas)

                self._event_pos = max_pos

                # Expose current event processing position to prometheus
                synapse.metrics.event_processing_positions.labels("presence").set(
                    max_pos
                )

    async def _handle_state_delta(self, deltas):
        """Process current state deltas to find new joins that need to be
        handled.
        """
        # A map of destination to a set of user state that they should receive
        presence_destinations = {}  # type: Dict[str, Set[UserPresenceState]]

        for delta in deltas:
            typ = delta["type"]
            state_key = delta["state_key"]
            room_id = delta["room_id"]
            event_id = delta["event_id"]
            prev_event_id = delta["prev_event_id"]

            logger.debug("Handling: %r %r, %s", typ, state_key, event_id)

            # Drop any event that isn't a membership join
            if typ != EventTypes.Member:
                continue

            if event_id is None:
                # state has been deleted, so this is not a join. We only care about
                # joins.
                continue

            event = await self.store.get_event(event_id, allow_none=True)
            if not event or event.content.get("membership") != Membership.JOIN:
                # We only care about joins
                continue

            if prev_event_id:
                prev_event = await self.store.get_event(prev_event_id, allow_none=True)
                if (
                    prev_event
                    and prev_event.content.get("membership") == Membership.JOIN
                ):
                    # Ignore changes to join events.
                    continue

            # Retrieve any user presence state updates that need to be sent as a result,
            # and the destinations that need to receive it
            destinations, user_presence_states = await self._on_user_joined_room(
                room_id, state_key
            )

            # Insert the destinations and respective updates into our destinations dict
            for destination in destinations:
                presence_destinations.setdefault(destination, set()).update(
                    user_presence_states
                )

        # Send out user presence updates for each destination
        for destination, user_state_set in presence_destinations.items():
            self.federation.send_presence_to_destinations(
                destinations=[destination], states=user_state_set
            )

    async def _on_user_joined_room(
        self, room_id: str, user_id: str
    ) -> Tuple[List[str], List[UserPresenceState]]:
        """Called when we detect a user joining the room via the current state
        delta stream. Returns the destinations that need to be updated and the
        presence updates to send to them.

        Args:
            room_id: The ID of the room that the user has joined.
            user_id: The ID of the user that has joined the room.

        Returns:
            A tuple of destinations and presence updates to send to them.
        """
        if self.is_mine_id(user_id):
            # If this is a local user then we need to send their presence
            # out to hosts in the room (who don't already have it)

            # TODO: We should be able to filter the hosts down to those that
            # haven't previously seen the user

            remote_hosts = await self.state.get_current_hosts_in_room(room_id)

            # Filter out ourselves.
            filtered_remote_hosts = [
                host for host in remote_hosts if host != self.server_name
            ]

            state = await self.current_state_for_user(user_id)
            return filtered_remote_hosts, [state]
        else:
            # A remote user has joined the room, so we need to:
            #   1. Check if this is a new server in the room
            #   2. If so send any presence they don't already have for
            #      local users in the room.

            # TODO: We should be able to filter the users down to those that
            # the server hasn't previously seen

            # TODO: Check that this is actually a new server joining the
            # room.

            remote_host = get_domain_from_id(user_id)

            users = await self.state.get_current_users_in_room(room_id)
            user_ids = list(filter(self.is_mine_id, users))

            states_d = await self.current_state_for_users(user_ids)

            # Filter out old presence, i.e. offline presence states where
            # the user hasn't been active for a week. We can change this
            # depending on what we want the UX to be, but at the least we
            # should filter out offline presence where the state is just the
            # default state.
            now = self.clock.time_msec()
            states = [
                state
                for state in states_d.values()
                if state.state != PresenceState.OFFLINE
                or now - state.last_active_ts < 7 * 24 * 60 * 60 * 1000
                or state.status_msg is not None
            ]

            return [remote_host], states


def should_notify(old_state, new_state):
    """Decides if a presence state change should be sent to interested parties."""
    if old_state == new_state:
        return False

    if old_state.status_msg != new_state.status_msg:
        notify_reason_counter.labels("status_msg_change").inc()
        return True

    if old_state.state != new_state.state:
        notify_reason_counter.labels("state_change").inc()
        state_transition_counter.labels(old_state.state, new_state.state).inc()
        return True

    if old_state.state == PresenceState.ONLINE:
        if new_state.currently_active != old_state.currently_active:
            notify_reason_counter.labels("current_active_change").inc()
            return True

        if (
            new_state.last_active_ts - old_state.last_active_ts
            > LAST_ACTIVE_GRANULARITY
        ):
            # Only notify about last active bumps if we're not currently active
            if not new_state.currently_active:
                notify_reason_counter.labels("last_active_change_online").inc()
                return True

    elif new_state.last_active_ts - old_state.last_active_ts > LAST_ACTIVE_GRANULARITY:
        # Always notify for a transition where last active gets bumped.
        notify_reason_counter.labels("last_active_change_not_online").inc()
        return True

    return False


def format_user_presence_state(state, now, include_user_id=True):
    """Convert UserPresenceState to a format that can be sent down to clients
    and to other servers.

    The "user_id" is optional so that this function can be used to format presence
    updates for client /sync responses and for federation /send requests.
    """
    content = {"presence": state.state}
    if include_user_id:
        content["user_id"] = state.user_id
    if state.last_active_ts:
        content["last_active_ago"] = now - state.last_active_ts
    if state.status_msg and state.state != PresenceState.OFFLINE:
        content["status_msg"] = state.status_msg
    if state.state == PresenceState.ONLINE:
        content["currently_active"] = state.currently_active

    return content


class PresenceEventSource:
    def __init__(self, hs: "HomeServer"):
        # We can't call get_presence_handler here because there's a cycle:
        #
        #   Presence -> Notifier -> PresenceEventSource -> Presence
        #
        # Same with get_module_api, get_presence_router
        #
        #   AuthHandler -> Notifier -> PresenceEventSource -> ModuleApi -> AuthHandler
        self.get_presence_handler = hs.get_presence_handler
        self.get_module_api = hs.get_module_api
        self.get_presence_router = hs.get_presence_router
        self.clock = hs.get_clock()
        self.store = hs.get_datastore()
        self.state = hs.get_state_handler()

    @log_function
    async def get_new_events(
        self,
        user,
        from_key,
        room_ids=None,
        include_offline=True,
        explicit_room_id=None,
        **kwargs,
    ) -> Tuple[List[UserPresenceState], int]:
        # The process for getting presence events are:
        #  1. Get the rooms the user is in.
        #  2. Get the list of user in the rooms.
        #  3. Get the list of users that are in the user's presence list.
        #  4. If there is a from_key set, cross reference the list of users
        #     with the `presence_stream_cache` to see which ones we actually
        #     need to check.
        #  5. Load current state for the users.
        #
        # We don't try and limit the presence updates by the current token, as
        # sending down the rare duplicate is not a concern.

        user_id = user.to_string()
        stream_change_cache = self.store.presence_stream_cache

        with Measure(self.clock, "presence.get_new_events"):
            if user_id in self.get_module_api()._send_full_presence_to_local_users:
                # This user has been specified by a module to receive all current, online
                # user presence. Removing from_key and setting include_offline to false
                # will do effectively this.
                from_key = None
                include_offline = False

            if from_key is not None:
                from_key = int(from_key)

            max_token = self.store.get_current_presence_token()
            if from_key == max_token:
                # This is necessary as due to the way stream ID generators work
                # we may get updates that have a stream ID greater than the max
                # token (e.g. max_token is N but stream generator may return
                # results for N+2, due to N+1 not having finished being
                # persisted yet).
                #
                # This is usually fine, as it just means that we may send down
                # some presence updates multiple times. However, we need to be
                # careful that the sync stream either actually does make some
                # progress or doesn't return, otherwise clients will end up
                # tight looping calling /sync due to it immediately returning
                # the same token repeatedly.
                #
                # Hence this guard where we just return nothing so that the sync
                # doesn't return. C.f. #5503.
                return [], max_token

            # Figure out which other users this user should receive updates for
            users_interested_in = await self._get_interested_in(user, explicit_room_id)

            # We have a set of users that we're interested in the presence of. We want to
            # cross-reference that with the users that have actually changed their presence.

            # Check whether this user should see all user updates

            if users_interested_in == PresenceRouter.ALL_USERS:
                # Provide presence state for all users
                presence_updates = await self._filter_all_presence_updates_for_user(
                    user_id, include_offline, from_key
                )

                # Remove the user from the list of users to receive all presence
                if user_id in self.get_module_api()._send_full_presence_to_local_users:
                    self.get_module_api()._send_full_presence_to_local_users.remove(
                        user_id
                    )

                return presence_updates, max_token

            # Make mypy happy. users_interested_in should now be a set
            assert not isinstance(users_interested_in, str)

            # The set of users that we're interested in and that have had a presence update.
            # We'll actually pull the presence updates for these users at the end.
            interested_and_updated_users = (
                set()
            )  # type: Union[Set[str], FrozenSet[str]]

            if from_key:
                # First get all users that have had a presence update
                updated_users = stream_change_cache.get_all_entities_changed(from_key)

                # Cross-reference users we're interested in with those that have had updates.
                # Use a slightly-optimised method for processing smaller sets of updates.
                if updated_users is not None and len(updated_users) < 500:
                    # For small deltas, it's quicker to get all changes and then
                    # cross-reference with the users we're interested in
                    get_updates_counter.labels("stream").inc()
                    for other_user_id in updated_users:
                        if other_user_id in users_interested_in:
                            # mypy thinks this variable could be a FrozenSet as it's possibly set
                            # to one in the `get_entities_changed` call below, and `add()` is not
                            # method on a FrozenSet. That doesn't affect us here though, as
                            # `interested_and_updated_users` is clearly a set() above.
                            interested_and_updated_users.add(other_user_id)  # type: ignore
                else:
                    # Too many possible updates. Find all users we can see and check
                    # if any of them have changed.
                    get_updates_counter.labels("full").inc()

                    interested_and_updated_users = (
                        stream_change_cache.get_entities_changed(
                            users_interested_in, from_key
                        )
                    )
            else:
                # No from_key has been specified. Return the presence for all users
                # this user is interested in
                interested_and_updated_users = users_interested_in

            # Retrieve the current presence state for each user
            users_to_state = await self.get_presence_handler().current_state_for_users(
                interested_and_updated_users
            )
            presence_updates = list(users_to_state.values())

        # Remove the user from the list of users to receive all presence
        if user_id in self.get_module_api()._send_full_presence_to_local_users:
            self.get_module_api()._send_full_presence_to_local_users.remove(user_id)

        if not include_offline:
            # Filter out offline presence states
            presence_updates = self._filter_offline_presence_state(presence_updates)

        return presence_updates, max_token

    async def _filter_all_presence_updates_for_user(
        self,
        user_id: str,
        include_offline: bool,
        from_key: Optional[int] = None,
    ) -> List[UserPresenceState]:
        """
        Computes the presence updates a user should receive.

        First pulls presence updates from the database. Then consults PresenceRouter
        for whether any updates should be excluded by user ID.

        Args:
            user_id: The User ID of the user to compute presence updates for.
            include_offline: Whether to include offline presence states from the results.
            from_key: The minimum stream ID of updates to pull from the database
                before filtering.

        Returns:
            A list of presence states for the given user to receive.
        """
        if from_key:
            # Only return updates since the last sync
            updated_users = self.store.presence_stream_cache.get_all_entities_changed(
                from_key
            )
            if not updated_users:
                updated_users = []

            # Get the actual presence update for each change
            users_to_state = await self.get_presence_handler().current_state_for_users(
                updated_users
            )
            presence_updates = list(users_to_state.values())

            if not include_offline:
                # Filter out offline states
                presence_updates = self._filter_offline_presence_state(presence_updates)
        else:
            users_to_state = await self.store.get_presence_for_all_users(
                include_offline=include_offline
            )

            presence_updates = list(users_to_state.values())

        # TODO: This feels wildly inefficient, and it's unfortunate we need to ask the
        # module for information on a number of users when we then only take the info
        # for a single user

        # Filter through the presence router
        users_to_state_set = await self.get_presence_router().get_users_for_states(
            presence_updates
        )

        # We only want the mapping for the syncing user
        presence_updates = list(users_to_state_set[user_id])

        # Return presence information for all users
        return presence_updates

    def _filter_offline_presence_state(
        self, presence_updates: Iterable[UserPresenceState]
    ) -> List[UserPresenceState]:
        """Given an iterable containing user presence updates, return a list with any offline
        presence states removed.

        Args:
            presence_updates: Presence states to filter

        Returns:
            A new list with any offline presence states removed.
        """
        return [
            update
            for update in presence_updates
            if update.state != PresenceState.OFFLINE
        ]

    def get_current_key(self):
        return self.store.get_current_presence_token()

    @cached(num_args=2, cache_context=True)
    async def _get_interested_in(
        self,
        user: UserID,
        explicit_room_id: Optional[str] = None,
        cache_context: Optional[_CacheContext] = None,
    ) -> Union[Set[str], str]:
        """Returns the set of users that the given user should see presence
        updates for.

        Args:
            user: The user to retrieve presence updates for.
            explicit_room_id: The users that are in the room will be returned.

        Returns:
            A set of user IDs to return presence updates for, or "ALL" to return all
            known updates.
        """
        user_id = user.to_string()
        users_interested_in = set()
        users_interested_in.add(user_id)  # So that we receive our own presence

        # cache_context isn't likely to ever be None due to the @cached decorator,
        # but we can't have a non-optional argument after the optional argument
        # explicit_room_id either. Assert cache_context is not None so we can use it
        # without mypy complaining.
        assert cache_context

        # Check with the presence router whether we should poll additional users for
        # their presence information
        additional_users = await self.get_presence_router().get_interested_users(
            user.to_string()
        )
        if additional_users == PresenceRouter.ALL_USERS:
            # If the module requested that this user see the presence updates of *all*
            # users, then simply return that instead of calculating what rooms this
            # user shares
            return PresenceRouter.ALL_USERS

        # Add the additional users from the router
        users_interested_in.update(additional_users)

        # Find the users who share a room with this user
        users_who_share_room = await self.store.get_users_who_share_room_with_user(
            user_id, on_invalidate=cache_context.invalidate
        )
        users_interested_in.update(users_who_share_room)

        if explicit_room_id:
            user_ids = await self.store.get_users_in_room(
                explicit_room_id, on_invalidate=cache_context.invalidate
            )
            users_interested_in.update(user_ids)

        return users_interested_in


def handle_timeouts(user_states, is_mine_fn, syncing_user_ids, now):
    """Checks the presence of users that have timed out and updates as
    appropriate.

    Args:
        user_states(list): List of UserPresenceState's to check.
        is_mine_fn (fn): Function that returns if a user_id is ours
        syncing_user_ids (set): Set of user_ids with active syncs.
        now (int): Current time in ms.

    Returns:
        List of UserPresenceState updates
    """
    changes = {}  # Actual changes we need to notify people about

    for state in user_states:
        is_mine = is_mine_fn(state.user_id)

        new_state = handle_timeout(state, is_mine, syncing_user_ids, now)
        if new_state:
            changes[state.user_id] = new_state

    return list(changes.values())


def handle_timeout(state, is_mine, syncing_user_ids, now):
    """Checks the presence of the user to see if any of the timers have elapsed

    Args:
        state (UserPresenceState)
        is_mine (bool): Whether the user is ours
        syncing_user_ids (set): Set of user_ids with active syncs.
        now (int): Current time in ms.

    Returns:
        A UserPresenceState update or None if no update.
    """
    if state.state == PresenceState.OFFLINE:
        # No timeouts are associated with offline states.
        return None

    changed = False
    user_id = state.user_id

    if is_mine:
        if state.state == PresenceState.ONLINE:
            if now - state.last_active_ts > IDLE_TIMER:
                # Currently online, but last activity ages ago so auto
                # idle
                state = state.copy_and_replace(state=PresenceState.UNAVAILABLE)
                changed = True
            elif now - state.last_active_ts > LAST_ACTIVE_GRANULARITY:
                # So that we send down a notification that we've
                # stopped updating.
                changed = True

        if now - state.last_federation_update_ts > FEDERATION_PING_INTERVAL:
            # Need to send ping to other servers to ensure they don't
            # timeout and set us to offline
            changed = True

        # If there are have been no sync for a while (and none ongoing),
        # set presence to offline
        if user_id not in syncing_user_ids:
            # If the user has done something recently but hasn't synced,
            # don't set them as offline.
            sync_or_active = max(state.last_user_sync_ts, state.last_active_ts)
            if now - sync_or_active > SYNC_ONLINE_TIMEOUT:
                state = state.copy_and_replace(
                    state=PresenceState.OFFLINE, status_msg=None
                )
                changed = True
    else:
        # We expect to be poked occasionally by the other side.
        # This is to protect against forgetful/buggy servers, so that
        # no one gets stuck online forever.
        if now - state.last_federation_update_ts > FEDERATION_TIMEOUT:
            # The other side seems to have disappeared.
            state = state.copy_and_replace(state=PresenceState.OFFLINE, status_msg=None)
            changed = True

    return state if changed else None


def handle_update(prev_state, new_state, is_mine, wheel_timer, now):
    """Given a presence update:
        1. Add any appropriate timers.
        2. Check if we should notify anyone.

    Args:
        prev_state (UserPresenceState)
        new_state (UserPresenceState)
        is_mine (bool): Whether the user is ours
        wheel_timer (WheelTimer)
        now (int): Time now in ms

    Returns:
        3-tuple: `(new_state, persist_and_notify, federation_ping)` where:
            - new_state: is the state to actually persist
            - persist_and_notify (bool): whether to persist and notify people
            - federation_ping (bool): whether we should send a ping over federation
    """
    user_id = new_state.user_id

    persist_and_notify = False
    federation_ping = False

    # If the users are ours then we want to set up a bunch of timers
    # to time things out.
    if is_mine:
        if new_state.state == PresenceState.ONLINE:
            # Idle timer
            wheel_timer.insert(
                now=now, obj=user_id, then=new_state.last_active_ts + IDLE_TIMER
            )

            active = now - new_state.last_active_ts < LAST_ACTIVE_GRANULARITY
            new_state = new_state.copy_and_replace(currently_active=active)

            if active:
                wheel_timer.insert(
                    now=now,
                    obj=user_id,
                    then=new_state.last_active_ts + LAST_ACTIVE_GRANULARITY,
                )

        if new_state.state != PresenceState.OFFLINE:
            # User has stopped syncing
            wheel_timer.insert(
                now=now,
                obj=user_id,
                then=new_state.last_user_sync_ts + SYNC_ONLINE_TIMEOUT,
            )

            last_federate = new_state.last_federation_update_ts
            if now - last_federate > FEDERATION_PING_INTERVAL:
                # Been a while since we've poked remote servers
                new_state = new_state.copy_and_replace(last_federation_update_ts=now)
                federation_ping = True

    else:
        wheel_timer.insert(
            now=now,
            obj=user_id,
            then=new_state.last_federation_update_ts + FEDERATION_TIMEOUT,
        )

    # Check whether the change was something worth notifying about
    if should_notify(prev_state, new_state):
        new_state = new_state.copy_and_replace(last_federation_update_ts=now)
        persist_and_notify = True

    return new_state, persist_and_notify, federation_ping


async def get_interested_parties(
    store: DataStore, presence_router: PresenceRouter, states: List[UserPresenceState]
) -> Tuple[Dict[str, List[UserPresenceState]], Dict[str, List[UserPresenceState]]]:
    """Given a list of states return which entities (rooms, users)
    are interested in the given states.

    Args:
        store: The homeserver's data store.
        presence_router: A module for augmenting the destinations for presence updates.
        states: A list of incoming user presence updates.

    Returns:
        A 2-tuple of `(room_ids_to_states, users_to_states)`,
        with each item being a dict of `entity_name` -> `[UserPresenceState]`
    """
    room_ids_to_states = {}  # type: Dict[str, List[UserPresenceState]]
    users_to_states = {}  # type: Dict[str, List[UserPresenceState]]
    for state in states:
        room_ids = await store.get_rooms_for_user(state.user_id)
        for room_id in room_ids:
            room_ids_to_states.setdefault(room_id, []).append(state)

        # Always notify self
        users_to_states.setdefault(state.user_id, []).append(state)

    # Ask a presence routing module for any additional parties if one
    # is loaded.
    router_users_to_states = await presence_router.get_users_for_states(states)

    # Update the dictionaries with additional destinations and state to send
    for user_id, user_states in router_users_to_states.items():
        users_to_states.setdefault(user_id, []).extend(user_states)

    return room_ids_to_states, users_to_states


async def get_interested_remotes(
    store: DataStore,
    presence_router: PresenceRouter,
    states: List[UserPresenceState],
    state_handler: StateHandler,
) -> List[Tuple[Collection[str], List[UserPresenceState]]]:
    """Given a list of presence states figure out which remote servers
    should be sent which.

    All the presence states should be for local users only.

    Args:
        store: The homeserver's data store.
        presence_router: A module for augmenting the destinations for presence updates.
        states: A list of incoming user presence updates.
        state_handler:

    Returns:
        A list of 2-tuples of destinations and states, where for
        each tuple the list of UserPresenceState should be sent to each
        destination
    """
    hosts_and_states = []  # type: List[Tuple[Collection[str], List[UserPresenceState]]]

    # First we look up the rooms each user is in (as well as any explicit
    # subscriptions), then for each distinct room we look up the remote
    # hosts in those rooms.
    room_ids_to_states, users_to_states = await get_interested_parties(
        store, presence_router, states
    )

    for room_id, states in room_ids_to_states.items():
        hosts = await state_handler.get_current_hosts_in_room(room_id)
        hosts_and_states.append((hosts, states))

    for user_id, states in users_to_states.items():
        host = get_domain_from_id(user_id)
        hosts_and_states.append(([host], states))

    return hosts_and_states
