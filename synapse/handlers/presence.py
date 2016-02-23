# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

from twisted.internet import defer, reactor
from contextlib import contextmanager

from synapse.api.errors import SynapseError
from synapse.api.constants import PresenceState
from synapse.storage.presence import UserPresenceState

from synapse.util.logcontext import preserve_fn
from synapse.util.logutils import log_function
from synapse.util.metrics import Measure
from synapse.util.wheel_timer import WheelTimer
from synapse.types import UserID
import synapse.metrics

from ._base import BaseHandler

import logging


logger = logging.getLogger(__name__)

metrics = synapse.metrics.get_metrics_for(__name__)

notified_presence_counter = metrics.register_counter("notified_presence")
federation_presence_out_counter = metrics.register_counter("federation_presence_out")
presence_updates_counter = metrics.register_counter("presence_updates")
timers_fired_counter = metrics.register_counter("timers_fired")
federation_presence_counter = metrics.register_counter("federation_presence")
bump_active_time_counter = metrics.register_counter("bump_active_time")


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

assert LAST_ACTIVE_GRANULARITY < IDLE_TIMER


def user_presence_changed(distributor, user, statuscache):
    return distributor.fire("user_presence_changed", user, statuscache)


def collect_presencelike_data(distributor, user, content):
    return distributor.fire("collect_presencelike_data", user, content)


class PresenceHandler(BaseHandler):

    def __init__(self, hs):
        super(PresenceHandler, self).__init__(hs)
        self.hs = hs
        self.clock = hs.get_clock()
        self.store = hs.get_datastore()
        self.wheel_timer = WheelTimer()
        self.notifier = hs.get_notifier()
        self.federation = hs.get_replication_layer()

        self.federation.register_edu_handler(
            "m.presence", self.incoming_presence
        )
        self.federation.register_edu_handler(
            "m.presence_invite",
            lambda origin, content: self.invite_presence(
                observed_user=UserID.from_string(content["observed_user"]),
                observer_user=UserID.from_string(content["observer_user"]),
            )
        )
        self.federation.register_edu_handler(
            "m.presence_accept",
            lambda origin, content: self.accept_presence(
                observed_user=UserID.from_string(content["observed_user"]),
                observer_user=UserID.from_string(content["observer_user"]),
            )
        )
        self.federation.register_edu_handler(
            "m.presence_deny",
            lambda origin, content: self.deny_presence(
                observed_user=UserID.from_string(content["observed_user"]),
                observer_user=UserID.from_string(content["observer_user"]),
            )
        )

        distributor = hs.get_distributor()
        distributor.observe("user_joined_room", self.user_joined_room)

        active_presence = self.store.take_presence_startup_info()

        # A dictionary of the current state of users. This is prefilled with
        # non-offline presence from the DB. We should fetch from the DB if
        # we can't find a users presence in here.
        self.user_to_current_state = {
            state.user_id: state
            for state in active_presence
        }

        now = self.clock.time_msec()
        for state in active_presence:
            self.wheel_timer.insert(
                now=now,
                obj=state.user_id,
                then=state.last_active_ts + IDLE_TIMER,
            )
            self.wheel_timer.insert(
                now=now,
                obj=state.user_id,
                then=state.last_user_sync_ts + SYNC_ONLINE_TIMEOUT,
            )
            if self.hs.is_mine_id(state.user_id):
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
        self.unpersisted_users_changes = set()

        reactor.addSystemEventTrigger("before", "shutdown", self._on_shutdown)

        self.serial_to_user = {}
        self._next_serial = 1

        # Keeps track of the number of *ongoing* syncs. While this is non zero
        # a user will never go offline.
        self.user_to_num_current_syncs = {}

        # Start a LoopingCall in 30s that fires every 5s.
        # The initial delay is to allow disconnected clients a chance to
        # reconnect before we treat them as offline.
        self.clock.call_later(
            0 * 1000,
            self.clock.looping_call,
            self._handle_timeouts,
            5000,
        )

        metrics.register_callback("wheel_timer_size", lambda: len(self.wheel_timer))

    @defer.inlineCallbacks
    def _on_shutdown(self):
        """Gets called when shutting down. This lets us persist any updates that
        we haven't yet persisted, e.g. updates that only changes some internal
        timers. This allows changes to persist across startup without having to
        persist every single change.

        If this does not run it simply means that some of the timers will fire
        earlier than they should when synapse is restarted. This affect of this
        is some spurious presence changes that will self-correct.
        """
        logger.info(
            "Performing _on_shutdown. Persiting %d unpersisted changes",
            len(self.user_to_current_state)
        )

        if self.unpersisted_users_changes:
            yield self.store.update_presence([
                self.user_to_current_state[user_id]
                for user_id in self.unpersisted_users_changes
            ])
        logger.info("Finished _on_shutdown")

    @defer.inlineCallbacks
    def _update_states(self, new_states):
        """Updates presence of users. Sets the appropriate timeouts. Pokes
        the notifier and federation if and only if the changed presence state
        should be sent to clients/servers.
        """
        now = self.clock.time_msec()

        with Measure(self.clock, "presence_update_states"):

            # NOTE: We purposefully don't yield between now and when we've
            # calculated what we want to do with the new states, to avoid races.

            to_notify = {}  # Changes we want to notify everyone about
            to_federation_ping = {}  # These need sending keep-alives

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
                    prev_state, new_state,
                    is_mine=self.hs.is_mine_id(user_id),
                    wheel_timer=self.wheel_timer,
                    now=now
                )

                self.user_to_current_state[user_id] = new_state

                if should_notify:
                    to_notify[user_id] = new_state
                elif should_ping:
                    to_federation_ping[user_id] = new_state

            # TODO: We should probably ensure there are no races hereafter

            presence_updates_counter.inc_by(len(new_states))

            if to_notify:
                notified_presence_counter.inc_by(len(to_notify))
                yield self._persist_and_notify(to_notify.values())

            self.unpersisted_users_changes |= set(s.user_id for s in new_states)
            self.unpersisted_users_changes -= set(to_notify.keys())

            to_federation_ping = {
                user_id: state for user_id, state in to_federation_ping.items()
                if user_id not in to_notify
            }
            if to_federation_ping:
                federation_presence_out_counter.inc_by(len(to_federation_ping))

                _, _, hosts_to_states = yield self._get_interested_parties(
                    to_federation_ping.values()
                )

                self._push_to_remotes(hosts_to_states)

    def _handle_timeouts(self):
        """Checks the presence of users that have timed out and updates as
        appropriate.
        """
        now = self.clock.time_msec()

        with Measure(self.clock, "presence_handle_timeouts"):
            # Fetch the list of users that *may* have timed out. Things may have
            # changed since the timeout was set, so we won't necessarily have to
            # take any action.
            users_to_check = self.wheel_timer.fetch(now)

            states = [
                self.user_to_current_state.get(
                    user_id, UserPresenceState.default(user_id)
                )
                for user_id in set(users_to_check)
            ]

            timers_fired_counter.inc_by(len(states))

            changes = handle_timeouts(
                states,
                is_mine_fn=self.hs.is_mine_id,
                user_to_num_current_syncs=self.user_to_num_current_syncs,
                now=now,
            )

        preserve_fn(self._update_states)(changes)

    @defer.inlineCallbacks
    def bump_presence_active_time(self, user):
        """We've seen the user do something that indicates they're interacting
        with the app.
        """
        user_id = user.to_string()

        bump_active_time_counter.inc()

        prev_state = yield self.current_state_for_user(user_id)

        new_fields = {
            "last_active_ts": self.clock.time_msec(),
        }
        if prev_state.state == PresenceState.UNAVAILABLE:
            new_fields["state"] = PresenceState.ONLINE

        yield self._update_states([prev_state.copy_and_replace(**new_fields)])

    @defer.inlineCallbacks
    def user_syncing(self, user_id, affect_presence=True):
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
        if affect_presence:
            curr_sync = self.user_to_num_current_syncs.get(user_id, 0)
            self.user_to_num_current_syncs[user_id] = curr_sync + 1

            prev_state = yield self.current_state_for_user(user_id)
            if prev_state.state == PresenceState.OFFLINE:
                # If they're currently offline then bring them online, otherwise
                # just update the last sync times.
                yield self._update_states([prev_state.copy_and_replace(
                    state=PresenceState.ONLINE,
                    last_active_ts=self.clock.time_msec(),
                    last_user_sync_ts=self.clock.time_msec(),
                )])
            else:
                yield self._update_states([prev_state.copy_and_replace(
                    last_user_sync_ts=self.clock.time_msec(),
                )])

        @defer.inlineCallbacks
        def _end():
            if affect_presence:
                self.user_to_num_current_syncs[user_id] -= 1

                prev_state = yield self.current_state_for_user(user_id)
                yield self._update_states([prev_state.copy_and_replace(
                    last_user_sync_ts=self.clock.time_msec(),
                )])

        @contextmanager
        def _user_syncing():
            try:
                yield
            finally:
                preserve_fn(_end)()

        defer.returnValue(_user_syncing())

    @defer.inlineCallbacks
    def current_state_for_user(self, user_id):
        """Get the current presence state for a user.
        """
        res = yield self.current_state_for_users([user_id])
        defer.returnValue(res[user_id])

    @defer.inlineCallbacks
    def current_state_for_users(self, user_ids):
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
            res = yield self.store.get_presence_for_users(missing)
            states.update({state.user_id: state for state in res})

            missing = [user_id for user_id, state in states.items() if not state]
            if missing:
                new = {
                    user_id: UserPresenceState.default(user_id)
                    for user_id in missing
                }
                states.update(new)
                self.user_to_current_state.update(new)

        defer.returnValue(states)

    @defer.inlineCallbacks
    def _get_interested_parties(self, states):
        """Given a list of states return which entities (rooms, users, servers)
        are interested in the given states.

        Returns:
            3-tuple: `(room_ids_to_states, users_to_states, hosts_to_states)`,
            with each item being a dict of `entity_name` -> `[UserPresenceState]`
        """
        room_ids_to_states = {}
        users_to_states = {}
        for state in states:
            events = yield self.store.get_rooms_for_user(state.user_id)
            for e in events:
                room_ids_to_states.setdefault(e.room_id, []).append(state)

            plist = yield self.store.get_presence_list_observers_accepted(state.user_id)
            for u in plist:
                users_to_states.setdefault(u, []).append(state)

            # Always notify self
            users_to_states.setdefault(state.user_id, []).append(state)

        hosts_to_states = {}
        for room_id, states in room_ids_to_states.items():
            local_states = filter(lambda s: self.hs.is_mine_id(s.user_id), states)
            if not local_states:
                continue

            hosts = yield self.store.get_joined_hosts_for_room(room_id)
            for host in hosts:
                hosts_to_states.setdefault(host, []).extend(local_states)

        for user_id, states in users_to_states.items():
            local_states = filter(lambda s: self.hs.is_mine_id(s.user_id), states)
            if not local_states:
                continue

            host = UserID.from_string(user_id).domain
            hosts_to_states.setdefault(host, []).extend(local_states)

        # TODO: de-dup hosts_to_states, as a single host might have multiple
        # of same presence

        defer.returnValue((room_ids_to_states, users_to_states, hosts_to_states))

    @defer.inlineCallbacks
    def _persist_and_notify(self, states):
        """Persist states in the database, poke the notifier and send to
        interested remote servers
        """
        stream_id, max_token = yield self.store.update_presence(states)

        parties = yield self._get_interested_parties(states)
        room_ids_to_states, users_to_states, hosts_to_states = parties

        self.notifier.on_new_event(
            "presence_key", stream_id, rooms=room_ids_to_states.keys(),
            users=[UserID.from_string(u) for u in users_to_states.keys()]
        )

        self._push_to_remotes(hosts_to_states)

    def _push_to_remotes(self, hosts_to_states):
        """Sends state updates to remote servers.

        Args:
            hosts_to_states (dict): Mapping `server_name` -> `[UserPresenceState]`
        """
        now = self.clock.time_msec()
        for host, states in hosts_to_states.items():
            self.federation.send_edu(
                destination=host,
                edu_type="m.presence",
                content={
                    "push": [
                        _format_user_presence_state(state, now)
                        for state in states
                    ]
                }
            )

    @defer.inlineCallbacks
    def incoming_presence(self, origin, content):
        """Called when we receive a `m.presence` EDU from a remote server.
        """
        now = self.clock.time_msec()
        updates = []
        for push in content.get("push", []):
            # A "push" contains a list of presence that we are probably interested
            # in.
            # TODO: Actually check if we're interested, rather than blindly
            # accepting presence updates.
            user_id = push.get("user_id", None)
            if not user_id:
                logger.info(
                    "Got presence update from %r with no 'user_id': %r",
                    origin, push,
                )
                continue

            presence_state = push.get("presence", None)
            if not presence_state:
                logger.info(
                    "Got presence update from %r with no 'presence_state': %r",
                    origin, push,
                )
                continue

            new_fields = {
                "state": presence_state,
                "last_federation_update_ts": now,
            }

            last_active_ago = push.get("last_active_ago", None)
            if last_active_ago is not None:
                new_fields["last_active_ts"] = now - last_active_ago

            new_fields["status_msg"] = push.get("status_msg", None)
            new_fields["currently_active"] = push.get("currently_active", False)

            prev_state = yield self.current_state_for_user(user_id)
            updates.append(prev_state.copy_and_replace(**new_fields))

        if updates:
            federation_presence_counter.inc_by(len(updates))
            yield self._update_states(updates)

    @defer.inlineCallbacks
    def get_state(self, target_user, as_event=False):
        results = yield self.get_states(
            [target_user.to_string()],
            as_event=as_event,
        )

        defer.returnValue(results[0])

    @defer.inlineCallbacks
    def get_states(self, target_user_ids, as_event=False):
        """Get the presence state for users.

        Args:
            target_user_ids (list)
            as_event (bool): Whether to format it as a client event or not.

        Returns:
            list
        """

        updates = yield self.current_state_for_users(target_user_ids)
        updates = updates.values()

        for user_id in set(target_user_ids) - set(u.user_id for u in updates):
            updates.append(UserPresenceState.default(user_id))

        now = self.clock.time_msec()
        if as_event:
            defer.returnValue([
                {
                    "type": "m.presence",
                    "content": _format_user_presence_state(state, now),
                }
                for state in updates
            ])
        else:
            defer.returnValue([
                _format_user_presence_state(state, now) for state in updates
            ])

    @defer.inlineCallbacks
    def set_state(self, target_user, state):
        """Set the presence state of the user.
        """
        status_msg = state.get("status_msg", None)
        presence = state["presence"]

        valid_presence = (
            PresenceState.ONLINE, PresenceState.UNAVAILABLE, PresenceState.OFFLINE
        )
        if presence not in valid_presence:
            raise SynapseError(400, "Invalid presence state")

        user_id = target_user.to_string()

        prev_state = yield self.current_state_for_user(user_id)

        new_fields = {
            "state": presence,
            "status_msg": status_msg if presence != PresenceState.OFFLINE else None
        }

        if presence == PresenceState.ONLINE:
            new_fields["last_active_ts"] = self.clock.time_msec()

        yield self._update_states([prev_state.copy_and_replace(**new_fields)])

    @defer.inlineCallbacks
    def user_joined_room(self, user, room_id):
        """Called (via the distributor) when a user joins a room. This funciton
        sends presence updates to servers, either:
            1. the joining user is a local user and we send their presence to
               all servers in the room.
            2. the joining user is a remote user and so we send presence for all
               local users in the room.
        """
        # We only need to send presence to servers that don't have it yet. We
        # don't need to send to local clients here, as that is done as part
        # of the event stream/sync.
        # TODO: Only send to servers not already in the room.
        if self.hs.is_mine(user):
            state = yield self.current_state_for_user(user.to_string())

            hosts = yield self.store.get_joined_hosts_for_room(room_id)
            self._push_to_remotes({host: (state,) for host in hosts})
        else:
            user_ids = yield self.store.get_users_in_room(room_id)
            user_ids = filter(self.hs.is_mine_id, user_ids)

            states = yield self.current_state_for_users(user_ids)

            self._push_to_remotes({user.domain: states.values()})

    @defer.inlineCallbacks
    def get_presence_list(self, observer_user, accepted=None):
        """Returns the presence for all users in their presence list.
        """
        if not self.hs.is_mine(observer_user):
            raise SynapseError(400, "User is not hosted on this Home Server")

        presence_list = yield self.store.get_presence_list(
            observer_user.localpart, accepted=accepted
        )

        results = yield self.get_states(
            target_user_ids=[row["observed_user_id"] for row in presence_list],
            as_event=False,
        )

        is_accepted = {
            row["observed_user_id"]: row["accepted"] for row in presence_list
        }

        for result in results:
            result.update({
                "accepted": is_accepted,
            })

        defer.returnValue(results)

    @defer.inlineCallbacks
    def send_presence_invite(self, observer_user, observed_user):
        """Sends a presence invite.
        """
        yield self.store.add_presence_list_pending(
            observer_user.localpart, observed_user.to_string()
        )

        if self.hs.is_mine(observed_user):
            yield self.invite_presence(observed_user, observer_user)
        else:
            yield self.federation.send_edu(
                destination=observed_user.domain,
                edu_type="m.presence_invite",
                content={
                    "observed_user": observed_user.to_string(),
                    "observer_user": observer_user.to_string(),
                }
            )

    @defer.inlineCallbacks
    def invite_presence(self, observed_user, observer_user):
        """Handles new presence invites.
        """
        if not self.hs.is_mine(observed_user):
            raise SynapseError(400, "User is not hosted on this Home Server")

        # TODO: Don't auto accept
        if self.hs.is_mine(observer_user):
            yield self.accept_presence(observed_user, observer_user)
        else:
            self.federation.send_edu(
                destination=observer_user.domain,
                edu_type="m.presence_accept",
                content={
                    "observed_user": observed_user.to_string(),
                    "observer_user": observer_user.to_string(),
                }
            )

            state_dict = yield self.get_state(observed_user, as_event=False)

            self.federation.send_edu(
                destination=observer_user.domain,
                edu_type="m.presence",
                content={
                    "push": [state_dict]
                }
            )

    @defer.inlineCallbacks
    def accept_presence(self, observed_user, observer_user):
        """Handles a m.presence_accept EDU. Mark a presence invite from a
        local or remote user as accepted in a local user's presence list.
        Starts polling for presence updates from the local or remote user.
        Args:
            observed_user(UserID): The user to update in the presence list.
            observer_user(UserID): The owner of the presence list to update.
        """
        yield self.store.set_presence_list_accepted(
            observer_user.localpart, observed_user.to_string()
        )

    @defer.inlineCallbacks
    def deny_presence(self, observed_user, observer_user):
        """Handle a m.presence_deny EDU. Removes a local or remote user from a
        local user's presence list.
        Args:
            observed_user(UserID): The local or remote user to remove from the
                list.
            observer_user(UserID): The local owner of the presence list.
        Returns:
            A Deferred.
        """
        yield self.store.del_presence_list(
            observer_user.localpart, observed_user.to_string()
        )

        # TODO(paul): Inform the user somehow?

    @defer.inlineCallbacks
    def drop(self, observed_user, observer_user):
        """Remove a local or remote user from a local user's presence list and
        unsubscribe the local user from updates that user.
        Args:
            observed_user(UserId): The local or remote user to remove from the
                list.
            observer_user(UserId): The local owner of the presence list.
        Returns:
            A Deferred.
        """
        if not self.hs.is_mine(observer_user):
            raise SynapseError(400, "User is not hosted on this Home Server")

        yield self.store.del_presence_list(
            observer_user.localpart, observed_user.to_string()
        )

        # TODO: Inform the remote that we've dropped the presence list.

    @defer.inlineCallbacks
    def is_visible(self, observed_user, observer_user):
        """Returns whether a user can see another user's presence.
        """
        observer_rooms = yield self.store.get_rooms_for_user(observer_user.to_string())
        observed_rooms = yield self.store.get_rooms_for_user(observed_user.to_string())

        observer_room_ids = set(r.room_id for r in observer_rooms)
        observed_room_ids = set(r.room_id for r in observed_rooms)

        if observer_room_ids & observed_room_ids:
            defer.returnValue(True)

        accepted_observers = yield self.store.get_presence_list_observers_accepted(
            observed_user.to_string()
        )

        defer.returnValue(observer_user.to_string() in accepted_observers)


def should_notify(old_state, new_state):
    """Decides if a presence state change should be sent to interested parties.
    """
    if old_state.status_msg != new_state.status_msg:
        return True

    if old_state.state == PresenceState.ONLINE:
        if new_state.state != PresenceState.ONLINE:
            # Always notify for online -> anything
            return True

        if new_state.currently_active != old_state.currently_active:
            return True

    if new_state.last_active_ts - old_state.last_active_ts > LAST_ACTIVE_GRANULARITY:
        # Always notify for a transition where last active gets bumped.
        return True

    if old_state.state != new_state.state:
        return True

    return False


def _format_user_presence_state(state, now):
    """Convert UserPresenceState to a format that can be sent down to clients
    and to other servers.
    """
    content = {
        "presence": state.state,
        "user_id": state.user_id,
    }
    if state.last_active_ts:
        content["last_active_ago"] = now - state.last_active_ts
    if state.status_msg and state.state != PresenceState.OFFLINE:
        content["status_msg"] = state.status_msg
    if state.state == PresenceState.ONLINE:
        content["currently_active"] = state.currently_active

    return content


class PresenceEventSource(object):
    def __init__(self, hs):
        self.hs = hs
        self.clock = hs.get_clock()
        self.store = hs.get_datastore()

    @defer.inlineCallbacks
    @log_function
    def get_new_events(self, user, from_key, room_ids=None, include_offline=True,
                       **kwargs):
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

        with Measure(self.clock, "presence.get_new_events"):
            user_id = user.to_string()
            if from_key is not None:
                from_key = int(from_key)
            room_ids = room_ids or []

            presence = self.hs.get_handlers().presence_handler

            if not room_ids:
                rooms = yield self.store.get_rooms_for_user(user_id)
                room_ids = set(e.room_id for e in rooms)

            user_ids_to_check = set()
            for room_id in room_ids:
                users = yield self.store.get_users_in_room(room_id)
                user_ids_to_check.update(users)

            plist = yield self.store.get_presence_list_accepted(user.localpart)
            user_ids_to_check.update([row["observed_user_id"] for row in plist])

            # Always include yourself. Only really matters for when the user is
            # not in any rooms, but still.
            user_ids_to_check.add(user_id)

            max_token = self.store.get_current_presence_token()

            if from_key:
                user_ids_changed = self.store.presence_stream_cache.get_entities_changed(
                    user_ids_to_check, from_key,
                )
            else:
                user_ids_changed = user_ids_to_check

            updates = yield presence.current_state_for_users(user_ids_changed)

            now = self.clock.time_msec()

        defer.returnValue(([
            {
                "type": "m.presence",
                "content": _format_user_presence_state(s, now),
            }
            for s in updates.values()
            if include_offline or s.state != PresenceState.OFFLINE
        ], max_token))

    def get_current_key(self):
        return self.store.get_current_presence_token()

    def get_pagination_rows(self, user, pagination_config, key):
        return self.get_new_events(user, from_key=None, include_offline=False)


def handle_timeouts(user_states, is_mine_fn, user_to_num_current_syncs, now):
    """Checks the presence of users that have timed out and updates as
    appropriate.

    Args:
        user_states(list): List of UserPresenceState's to check.
        is_mine_fn (fn): Function that returns if a user_id is ours
        user_to_num_current_syncs (dict): Mapping of user_id to number of currently
            active syncs.
        now (int): Current time in ms.

    Returns:
        List of UserPresenceState updates
    """
    changes = {}  # Actual changes we need to notify people about

    for state in user_states:
        is_mine = is_mine_fn(state.user_id)

        new_state = handle_timeout(state, is_mine, user_to_num_current_syncs, now)
        if new_state:
            changes[state.user_id] = new_state

    return changes.values()


def handle_timeout(state, is_mine, user_to_num_current_syncs, now):
    """Checks the presence of the user to see if any of the timers have elapsed

    Args:
        state (UserPresenceState)
        is_mine (bool): Whether the user is ours
        user_to_num_current_syncs (dict): Mapping of user_id to number of currently
            active syncs.
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
                state = state.copy_and_replace(
                    state=PresenceState.UNAVAILABLE,
                )
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
        if not user_to_num_current_syncs.get(user_id, 0):
            if now - state.last_user_sync_ts > SYNC_ONLINE_TIMEOUT:
                state = state.copy_and_replace(
                    state=PresenceState.OFFLINE,
                    status_msg=None,
                )
                changed = True
    else:
        # We expect to be poked occaisonally by the other side.
        # This is to protect against forgetful/buggy servers, so that
        # no one gets stuck online forever.
        if now - state.last_federation_update_ts > FEDERATION_TIMEOUT:
            # The other side seems to have disappeared.
            state = state.copy_and_replace(
                state=PresenceState.OFFLINE,
                status_msg=None,
            )
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
                now=now,
                obj=user_id,
                then=new_state.last_active_ts + IDLE_TIMER
            )

            active = now - new_state.last_active_ts < LAST_ACTIVE_GRANULARITY
            new_state = new_state.copy_and_replace(
                currently_active=active,
            )

            if active:
                wheel_timer.insert(
                    now=now,
                    obj=user_id,
                    then=new_state.last_active_ts + LAST_ACTIVE_GRANULARITY
                )

        if new_state.state != PresenceState.OFFLINE:
            # User has stopped syncing
            wheel_timer.insert(
                now=now,
                obj=user_id,
                then=new_state.last_user_sync_ts + SYNC_ONLINE_TIMEOUT
            )

            last_federate = new_state.last_federation_update_ts
            if now - last_federate > FEDERATION_PING_INTERVAL:
                # Been a while since we've poked remote servers
                new_state = new_state.copy_and_replace(
                    last_federation_update_ts=now,
                )
                federation_ping = True

    else:
        wheel_timer.insert(
            now=now,
            obj=user_id,
            then=new_state.last_federation_update_ts + FEDERATION_TIMEOUT
        )

    # Check whether the change was something worth notifying about
    if should_notify(prev_state, new_state):
        new_state = new_state.copy_and_replace(
            last_federation_update_ts=now,
        )
        persist_and_notify = True

    return new_state, persist_and_notify, federation_ping
