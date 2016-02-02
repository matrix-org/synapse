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

from twisted.internet import defer

from synapse.api.errors import SynapseError, AuthError
from synapse.api.constants import PresenceState

from synapse.util.logcontext import PreserveLoggingContext
from synapse.util.logutils import log_function
from synapse.types import UserID
import synapse.metrics

from ._base import BaseHandler

import logging


logger = logging.getLogger(__name__)

metrics = synapse.metrics.get_metrics_for(__name__)


# Don't bother bumping "last active" time if it differs by less than 60 seconds
LAST_ACTIVE_GRANULARITY = 60 * 1000

# Keep no more than this number of offline serial revisions
MAX_OFFLINE_SERIALS = 1000


# TODO(paul): Maybe there's one of these I can steal from somewhere
def partition(l, func):
    """Partition the list by the result of func applied to each element."""
    ret = {}

    for x in l:
        key = func(x)
        if key not in ret:
            ret[key] = []
        ret[key].append(x)

    return ret


def partitionbool(l, func):
    def boolfunc(x):
        return bool(func(x))

    ret = partition(l, boolfunc)
    return ret.get(True, []), ret.get(False, [])


def user_presence_changed(distributor, user, statuscache):
    return distributor.fire("user_presence_changed", user, statuscache)


def collect_presencelike_data(distributor, user, content):
    return distributor.fire("collect_presencelike_data", user, content)


class PresenceHandler(BaseHandler):

    STATE_LEVELS = {
        PresenceState.OFFLINE: 0,
        PresenceState.UNAVAILABLE: 1,
        PresenceState.ONLINE: 2,
        PresenceState.FREE_FOR_CHAT: 3,
    }

    def __init__(self, hs):
        super(PresenceHandler, self).__init__(hs)

        self.homeserver = hs

        self.clock = hs.get_clock()

        distributor = hs.get_distributor()
        distributor.observe("registered_user", self.registered_user)

        distributor.observe(
            "started_user_eventstream", self.started_user_eventstream
        )
        distributor.observe(
            "stopped_user_eventstream", self.stopped_user_eventstream
        )

        distributor.observe("user_joined_room", self.user_joined_room)

        distributor.declare("collect_presencelike_data")

        distributor.declare("changed_presencelike_data")
        distributor.observe(
            "changed_presencelike_data", self.changed_presencelike_data
        )

        # outbound signal from the presence module to advertise when a user's
        # presence has changed
        distributor.declare("user_presence_changed")

        self.distributor = distributor

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

        # IN-MEMORY store, mapping local userparts to sets of local users to
        # be informed of state changes.
        self._local_pushmap = {}
        # map local users to sets of remote /domain names/ who are interested
        # in them
        self._remote_sendmap = {}
        # map remote users to sets of local users who're interested in them
        self._remote_recvmap = {}
        # list of (serial, set of(userids)) tuples, ordered by serial, latest
        # first
        self._remote_offline_serials = []

        # map any user to a UserPresenceCache
        self._user_cachemap = {}
        self._user_cachemap_latest_serial = 0

        # map room_ids to the latest presence serial for a member of that
        # room
        self._room_serials = {}

        metrics.register_callback(
            "userCachemap:size",
            lambda: len(self._user_cachemap),
        )

    def _get_or_make_usercache(self, user):
        """If the cache entry doesn't exist, initialise a new one."""
        if user not in self._user_cachemap:
            self._user_cachemap[user] = UserPresenceCache()
        return self._user_cachemap[user]

    def _get_or_offline_usercache(self, user):
        """If the cache entry doesn't exist, return an OFFLINE one but do not
        store it into the cache."""
        if user in self._user_cachemap:
            return self._user_cachemap[user]
        else:
            return UserPresenceCache()

    def registered_user(self, user):
        return self.store.create_presence(user.localpart)

    @defer.inlineCallbacks
    def is_presence_visible(self, observer_user, observed_user):
        assert(self.hs.is_mine(observed_user))

        if observer_user == observed_user:
            defer.returnValue(True)

        if (yield self.store.user_rooms_intersect(
                [u.to_string() for u in observer_user, observed_user])):
            defer.returnValue(True)

        if (yield self.store.is_presence_visible(
                observed_localpart=observed_user.localpart,
                observer_userid=observer_user.to_string())):
            defer.returnValue(True)

        defer.returnValue(False)

    @defer.inlineCallbacks
    def get_state(self, target_user, auth_user, as_event=False, check_auth=True):
        """Get the current presence state of the given user.

        Args:
            target_user (UserID): The user whose presence we want
            auth_user (UserID): The user requesting the presence, used for
                checking if said user is allowed to see the persence of the
                `target_user`
            as_event (bool): Format the return as an event or not?
            check_auth (bool): Perform the auth checks or not?

        Returns:
            dict: The presence state of the `target_user`, whose format depends
            on the `as_event` argument.
        """
        if self.hs.is_mine(target_user):
            if check_auth:
                visible = yield self.is_presence_visible(
                    observer_user=auth_user,
                    observed_user=target_user
                )

                if not visible:
                    raise SynapseError(404, "Presence information not visible")

            if target_user in self._user_cachemap:
                state = self._user_cachemap[target_user].get_state()
            else:
                state = yield self.store.get_presence_state(target_user.localpart)
                if "mtime" in state:
                    del state["mtime"]
                state["presence"] = state.pop("state")
        else:
            # TODO(paul): Have remote server send us permissions set
            state = self._get_or_offline_usercache(target_user).get_state()

        if "last_active" in state:
            state["last_active_ago"] = int(
                self.clock.time_msec() - state.pop("last_active")
            )

        if as_event:
            content = state

            content["user_id"] = target_user.to_string()

            if "last_active" in content:
                content["last_active_ago"] = int(
                    self._clock.time_msec() - content.pop("last_active")
                )

            defer.returnValue({"type": "m.presence", "content": content})
        else:
            defer.returnValue(state)

    @defer.inlineCallbacks
    def get_states(self, target_users, auth_user, as_event=False, check_auth=True):
        """A batched version of the `get_state` method that accepts a list of
        `target_users`

        Args:
            target_users (list): The list of UserID's whose presence we want
            auth_user (UserID): The user requesting the presence, used for
                checking if said user is allowed to see the persence of the
                `target_users`
            as_event (bool): Format the return as an event or not?
            check_auth (bool): Perform the auth checks or not?

        Returns:
            dict: A mapping from user -> presence_state
        """
        local_users, remote_users = partitionbool(
            target_users,
            lambda u: self.hs.is_mine(u)
        )

        if check_auth:
            for user in local_users:
                visible = yield self.is_presence_visible(
                    observer_user=auth_user,
                    observed_user=user
                )

                if not visible:
                    raise SynapseError(404, "Presence information not visible")

        results = {}
        if local_users:
            for user in local_users:
                if user in self._user_cachemap:
                    results[user] = self._user_cachemap[user].get_state()

            local_to_user = {u.localpart: u for u in local_users}

            states = yield self.store.get_presence_states(
                [u.localpart for u in local_users if u not in results]
            )

            for local_part, state in states.items():
                if state is None:
                    continue
                res = {"presence": state["state"]}
                if "status_msg" in state and state["status_msg"]:
                    res["status_msg"] = state["status_msg"]
                results[local_to_user[local_part]] = res

        for user in remote_users:
            # TODO(paul): Have remote server send us permissions set
            results[user] = self._get_or_offline_usercache(user).get_state()

        for state in results.values():
            if "last_active" in state:
                state["last_active_ago"] = int(
                    self.clock.time_msec() - state.pop("last_active")
                )

        if as_event:
            for user, state in results.items():
                content = state
                content["user_id"] = user.to_string()

                if "last_active" in content:
                    content["last_active_ago"] = int(
                        self._clock.time_msec() - content.pop("last_active")
                    )

                results[user] = {"type": "m.presence", "content": content}

        defer.returnValue(results)

    @defer.inlineCallbacks
    @log_function
    def set_state(self, target_user, auth_user, state):
        # return
        # TODO (erikj): Turn this back on. Why did we end up sending EDUs
        # everywhere?

        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "User is not hosted on this Home Server")

        if target_user != auth_user:
            raise AuthError(400, "Cannot set another user's presence")

        if "status_msg" not in state:
            state["status_msg"] = None

        for k in state.keys():
            if k not in ("presence", "status_msg"):
                raise SynapseError(
                    400, "Unexpected presence state key '%s'" % (k,)
                )

        if state["presence"] not in self.STATE_LEVELS:
            raise SynapseError(400, "'%s' is not a valid presence state" % (
                state["presence"],
            ))

        logger.debug("Updating presence state of %s to %s",
                     target_user.localpart, state["presence"])

        state_to_store = dict(state)
        state_to_store["state"] = state_to_store.pop("presence")

        statuscache = self._get_or_offline_usercache(target_user)
        was_level = self.STATE_LEVELS[statuscache.get_state()["presence"]]
        now_level = self.STATE_LEVELS[state["presence"]]

        yield self.store.set_presence_state(
            target_user.localpart, state_to_store
        )
        yield collect_presencelike_data(self.distributor, target_user, state)

        if now_level > was_level:
            state["last_active"] = self.clock.time_msec()

        now_online = state["presence"] != PresenceState.OFFLINE
        was_polling = target_user in self._user_cachemap

        if now_online and not was_polling:
            self.start_polling_presence(target_user, state=state)
        elif not now_online and was_polling:
            self.stop_polling_presence(target_user)

        # TODO(paul): perform a presence push as part of start/stop poll so
        #   we don't have to do this all the time
        yield self.changed_presencelike_data(target_user, state)

    def bump_presence_active_time(self, user, now=None):
        if now is None:
            now = self.clock.time_msec()

        prev_state = self._get_or_make_usercache(user)
        if now - prev_state.state.get("last_active", 0) < LAST_ACTIVE_GRANULARITY:
            return

        self.changed_presencelike_data(user, {"last_active": now})

    def get_joined_rooms_for_user(self, user):
        """Get the list of rooms a user is joined to.

        Args:
            user(UserID): The user.
        Returns:
            A Deferred of a list of room id strings.
        """
        rm_handler = self.homeserver.get_handlers().room_member_handler
        return rm_handler.get_joined_rooms_for_user(user)

    def get_joined_users_for_room_id(self, room_id):
        rm_handler = self.homeserver.get_handlers().room_member_handler
        return rm_handler.get_room_members(room_id)

    @defer.inlineCallbacks
    def changed_presencelike_data(self, user, state):
        """Updates the presence state of a local user.

        Args:
            user(UserID): The user being updated.
            state(dict): The new presence state for the user.
        Returns:
            A Deferred
        """
        self._user_cachemap_latest_serial += 1
        statuscache = yield self.update_presence_cache(user, state)
        yield self.push_presence(user, statuscache=statuscache)

    @log_function
    def started_user_eventstream(self, user):
        # TODO(paul): Use "last online" state
        return self.set_state(user, user, {"presence": PresenceState.ONLINE})

    @log_function
    def stopped_user_eventstream(self, user):
        # TODO(paul): Save current state as "last online" state
        return self.set_state(user, user, {"presence": PresenceState.OFFLINE})

    @defer.inlineCallbacks
    def user_joined_room(self, user, room_id):
        """Called via the distributor whenever a user joins a room.
        Notifies the new member of the presence of the current members.
        Notifies the current members of the room of the new member's presence.

        Args:
            user(UserID): The user who joined the room.
            room_id(str): The room id the user joined.
        """
        if self.hs.is_mine(user):
            # No actual update but we need to bump the serial anyway for the
            # event source
            self._user_cachemap_latest_serial += 1
            statuscache = yield self.update_presence_cache(
                user, room_ids=[room_id]
            )
            self.push_update_to_local_and_remote(
                observed_user=user,
                room_ids=[room_id],
                statuscache=statuscache,
            )

        # We also want to tell them about current presence of people.
        curr_users = yield self.get_joined_users_for_room_id(room_id)

        for local_user in [c for c in curr_users if self.hs.is_mine(c)]:
            statuscache = yield self.update_presence_cache(
                local_user, room_ids=[room_id], add_to_cache=False
            )

            self.push_update_to_local_and_remote(
                observed_user=local_user,
                users_to_push=[user],
                statuscache=statuscache,
            )

    @defer.inlineCallbacks
    def send_presence_invite(self, observer_user, observed_user):
        """Request the presence of a local or remote user for a local user"""
        if not self.hs.is_mine(observer_user):
            raise SynapseError(400, "User is not hosted on this Home Server")

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
    def _should_accept_invite(self, observed_user, observer_user):
        if not self.hs.is_mine(observed_user):
            defer.returnValue(False)

        row = yield self.store.has_presence_state(observed_user.localpart)
        if not row:
            defer.returnValue(False)

        # TODO(paul): Eventually we'll ask the user's permission for this
        # before accepting. For now just accept any invite request
        defer.returnValue(True)

    @defer.inlineCallbacks
    def invite_presence(self, observed_user, observer_user):
        """Handles a m.presence_invite EDU. A remote or local user has
        requested presence updates for a local user. If the invite is accepted
        then allow the local or remote user to see the presence of the local
        user.

        Args:
            observed_user(UserID): The local user whose presence is requested.
            observer_user(UserID): The remote or local user requesting presence.
        """
        accept = yield self._should_accept_invite(observed_user, observer_user)

        if accept:
            yield self.store.allow_presence_visible(
                observed_user.localpart, observer_user.to_string()
            )

        if self.hs.is_mine(observer_user):
            if accept:
                yield self.accept_presence(observed_user, observer_user)
            else:
                yield self.deny_presence(observed_user, observer_user)
        else:
            edu_type = "m.presence_accept" if accept else "m.presence_deny"

            yield self.federation.send_edu(
                destination=observer_user.domain,
                edu_type=edu_type,
                content={
                    "observed_user": observed_user.to_string(),
                    "observer_user": observer_user.to_string(),
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

        self.start_polling_presence(
            observer_user, target_user=observed_user
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

        self.stop_polling_presence(
            observer_user, target_user=observed_user
        )

    @defer.inlineCallbacks
    def get_presence_list(self, observer_user, accepted=None):
        """Get the presence list for a local user. The retured list includes
        the current presence state for each user listed.

        Args:
            observer_user(UserID): The local user whose presence list to fetch.
            accepted(bool or None): If not none then only include users who
                have or have not accepted the presence invite request.
        Returns:
            A Deferred list of presence state events.
        """
        if not self.hs.is_mine(observer_user):
            raise SynapseError(400, "User is not hosted on this Home Server")

        presence_list = yield self.store.get_presence_list(
            observer_user.localpart, accepted=accepted
        )

        results = []
        for row in presence_list:
            observed_user = UserID.from_string(row["observed_user_id"])
            result = {
                "observed_user": observed_user, "accepted": row["accepted"]
            }
            result.update(
                self._get_or_offline_usercache(observed_user).get_state()
            )
            if "last_active" in result:
                result["last_active_ago"] = int(
                    self.clock.time_msec() - result.pop("last_active")
                )
            results.append(result)

        defer.returnValue(results)

    @defer.inlineCallbacks
    @log_function
    def start_polling_presence(self, user, target_user=None, state=None):
        """Subscribe a local user to presence updates from a local or remote
        user. If no target_user is supplied then subscribe to all users stored
        in the presence list for the local user.

        Additonally this pushes the current presence state of this user to all
        target_users. That state can be provided directly or will be read from
        the stored state for the local user.

        Also this attempts to notify the local user of the current state of
        any local target users.

        Args:
            user(UserID): The local user that whishes for presence updates.
            target_user(UserID): The local or remote user whose updates are
                wanted.
            state(dict): Optional presence state for the local user.
        """
        logger.debug("Start polling for presence from %s", user)

        if target_user:
            target_users = set([target_user])
            room_ids = []
        else:
            presence = yield self.store.get_presence_list(
                user.localpart, accepted=True
            )
            target_users = set([
                UserID.from_string(x["observed_user_id"]) for x in presence
            ])

            # Also include people in all my rooms

            room_ids = yield self.get_joined_rooms_for_user(user)

        if state is None:
            state = yield self.store.get_presence_state(user.localpart)
        else:
            # statuscache = self._get_or_make_usercache(user)
            # self._user_cachemap_latest_serial += 1
            # statuscache.update(state, self._user_cachemap_latest_serial)
            pass

        yield self.push_update_to_local_and_remote(
            observed_user=user,
            users_to_push=target_users,
            room_ids=room_ids,
            statuscache=self._get_or_make_usercache(user),
        )

        for target_user in target_users:
            if self.hs.is_mine(target_user):
                self._start_polling_local(user, target_user)

                # We want to tell the person that just came online
                # presence state of people they are interested in?
                self.push_update_to_clients(
                    users_to_push=[user],
                )

        deferreds = []
        remote_users = [u for u in target_users if not self.hs.is_mine(u)]
        remoteusers_by_domain = partition(remote_users, lambda u: u.domain)
        # Only poll for people in our get_presence_list
        for domain in remoteusers_by_domain:
            remoteusers = remoteusers_by_domain[domain]

            deferreds.append(self._start_polling_remote(
                user, domain, remoteusers
            ))

        yield defer.DeferredList(deferreds, consumeErrors=True)

    def _start_polling_local(self, user, target_user):
        """Subscribe a local user to presence updates for a local user

        Args:
            user(UserId): The local user that wishes for updates.
            target_user(UserId): The local users whose updates are wanted.
        """
        target_localpart = target_user.localpart

        if target_localpart not in self._local_pushmap:
            self._local_pushmap[target_localpart] = set()

        self._local_pushmap[target_localpart].add(user)

    def _start_polling_remote(self, user, domain, remoteusers):
        """Subscribe a local user to presence updates for remote users on a
        given remote domain.

        Args:
            user(UserID): The local user that wishes for updates.
            domain(str): The remote server the local user wants updates from.
            remoteusers(UserID): The remote users that local user wants to be
                told about.
        Returns:
            A Deferred.
        """
        to_poll = set()

        for u in remoteusers:
            if u not in self._remote_recvmap:
                self._remote_recvmap[u] = set()
                to_poll.add(u)

            self._remote_recvmap[u].add(user)

        if not to_poll:
            return defer.succeed(None)

        return self.federation.send_edu(
            destination=domain,
            edu_type="m.presence",
            content={"poll": [u.to_string() for u in to_poll]}
        )

    @log_function
    def stop_polling_presence(self, user, target_user=None):
        """Unsubscribe a local user from presence updates from a local or
        remote user. If no target user is supplied then unsubscribe the user
        from all presence updates that the user had subscribed to.

        Args:
            user(UserID): The local user that no longer wishes for updates.
            target_user(UserID or None): The user whose updates are no longer
                wanted.
        Returns:
            A Deferred.
        """
        logger.debug("Stop polling for presence from %s", user)

        if not target_user or self.hs.is_mine(target_user):
            self._stop_polling_local(user, target_user=target_user)

        deferreds = []

        if target_user:
            if target_user not in self._remote_recvmap:
                return
            target_users = set([target_user])
        else:
            target_users = self._remote_recvmap.keys()

        remoteusers = [u for u in target_users
                       if user in self._remote_recvmap[u]]
        remoteusers_by_domain = partition(remoteusers, lambda u: u.domain)

        for domain in remoteusers_by_domain:
            remoteusers = remoteusers_by_domain[domain]

            deferreds.append(
                self._stop_polling_remote(user, domain, remoteusers)
            )

        return defer.DeferredList(deferreds, consumeErrors=True)

    def _stop_polling_local(self, user, target_user):
        """Unsubscribe a local user from presence updates from a local user on
        this server.

        Args:
            user(UserID): The local user that no longer wishes for updates.
            target_user(UserID): The user whose updates are no longer wanted.
        """
        for localpart in self._local_pushmap.keys():
            if target_user and localpart != target_user.localpart:
                continue

            if user in self._local_pushmap[localpart]:
                self._local_pushmap[localpart].remove(user)

            if not self._local_pushmap[localpart]:
                del self._local_pushmap[localpart]

    @log_function
    def _stop_polling_remote(self, user, domain, remoteusers):
        """Unsubscribe a local user from presence updates from remote users on
        a given domain.

        Args:
            user(UserID): The local user that no longer wishes for updates.
            domain(str): The remote server to unsubscribe from.
            remoteusers([UserID]): The users on that remote server that the
                local user no longer wishes to be updated about.
        Returns:
            A Deferred.
        """
        to_unpoll = set()

        for u in remoteusers:
            self._remote_recvmap[u].remove(user)

            if not self._remote_recvmap[u]:
                del self._remote_recvmap[u]
                to_unpoll.add(u)

        if not to_unpoll:
            return defer.succeed(None)

        return self.federation.send_edu(
            destination=domain,
            edu_type="m.presence",
            content={"unpoll": [u.to_string() for u in to_unpoll]}
        )

    @defer.inlineCallbacks
    @log_function
    def push_presence(self, user, statuscache):
        """
        Notify local and remote users of a change in presence of a local user.
        Pushes the update to local clients and remote domains that are directly
        subscribed to the presence of the local user.
        Also pushes that update to any local user or remote domain that shares
        a room with the local user.

        Args:
            user(UserID): The local user whose presence was updated.
            statuscache(UserPresenceCache): Cache of the user's presence state
        Returns:
            A Deferred.
        """
        assert(self.hs.is_mine(user))

        logger.debug("Pushing presence update from %s", user)

        localusers = set(self._local_pushmap.get(user.localpart, set()))
        remotedomains = set(self._remote_sendmap.get(user.localpart, set()))

        # Reflect users' status changes back to themselves, so UIs look nice
        # and also user is informed of server-forced pushes
        localusers.add(user)

        room_ids = yield self.get_joined_rooms_for_user(user)

        if not localusers and not room_ids:
            defer.returnValue(None)

        yield self.push_update_to_local_and_remote(
            observed_user=user,
            users_to_push=localusers,
            remote_domains=remotedomains,
            room_ids=room_ids,
            statuscache=statuscache,
        )
        yield user_presence_changed(self.distributor, user, statuscache)

    @defer.inlineCallbacks
    def incoming_presence(self, origin, content):
        """Handle an incoming m.presence EDU.
        For each presence update in the "push" list update our local cache and
        notify the appropriate local clients. Only clients that share a room
        or are directly subscribed to the presence for a user should be
        notified of the update.
        For each subscription request in the "poll" list start pushing presence
        updates to the remote server.
        For unsubscribe request in the "unpoll" list stop pushing presence
        updates to the remote server.

        Args:
            orgin(str): The source of this m.presence EDU.
            content(dict): The content of this m.presence EDU.
        Returns:
            A Deferred.
        """
        deferreds = []

        for push in content.get("push", []):
            user = UserID.from_string(push["user_id"])

            logger.debug("Incoming presence update from %s", user)

            observers = set(self._remote_recvmap.get(user, set()))
            if observers:
                logger.debug(
                    " | %d interested local observers %r", len(observers), observers
                )

            room_ids = yield self.get_joined_rooms_for_user(user)
            if room_ids:
                logger.debug(" | %d interested room IDs %r", len(room_ids), room_ids)

            state = dict(push)
            del state["user_id"]

            if "presence" not in state:
                logger.warning(
                    "Received a presence 'push' EDU from %s without a"
                    " 'presence' key", origin
                )
                continue

            if "last_active_ago" in state:
                state["last_active"] = int(
                    self.clock.time_msec() - state.pop("last_active_ago")
                )

            self._user_cachemap_latest_serial += 1
            yield self.update_presence_cache(user, state, room_ids=room_ids)

            if not observers and not room_ids:
                logger.debug(" | no interested observers or room IDs")
                continue

            self.push_update_to_clients(
                users_to_push=observers, room_ids=room_ids
            )

            user_id = user.to_string()

            if state["presence"] == PresenceState.OFFLINE:
                self._remote_offline_serials.insert(
                    0,
                    (self._user_cachemap_latest_serial, set([user_id]))
                )
                while len(self._remote_offline_serials) > MAX_OFFLINE_SERIALS:
                    self._remote_offline_serials.pop()  # remove the oldest
                if user in self._user_cachemap:
                    del self._user_cachemap[user]
            else:
                # Remove the user from remote_offline_serials now that they're
                # no longer offline
                for idx, elem in enumerate(self._remote_offline_serials):
                    (_, user_ids) = elem
                    user_ids.discard(user_id)
                    if not user_ids:
                        self._remote_offline_serials.pop(idx)

        for poll in content.get("poll", []):
            user = UserID.from_string(poll)

            if not self.hs.is_mine(user):
                continue

            # TODO(paul) permissions checks

            if user not in self._remote_sendmap:
                self._remote_sendmap[user] = set()

            self._remote_sendmap[user].add(origin)

            deferreds.append(self._push_presence_remote(user, origin))

        for unpoll in content.get("unpoll", []):
            user = UserID.from_string(unpoll)

            if not self.hs.is_mine(user):
                continue

            if user in self._remote_sendmap:
                self._remote_sendmap[user].remove(origin)

                if not self._remote_sendmap[user]:
                    del self._remote_sendmap[user]

        yield defer.DeferredList(deferreds, consumeErrors=True)

    @defer.inlineCallbacks
    def update_presence_cache(self, user, state={}, room_ids=None,
                              add_to_cache=True):
        """Update the presence cache for a user with a new state and bump the
        serial to the latest value.

        Args:
            user(UserID): The user being updated
            state(dict): The presence state being updated
            room_ids(None or list of str): A list of room_ids to update. If
                room_ids is None then fetch the list of room_ids the user is
                joined to.
            add_to_cache: Whether to add an entry to the presence cache if the
                user isn't already in the cache.
        Returns:
            A Deferred UserPresenceCache for the user being updated.
        """
        if room_ids is None:
            room_ids = yield self.get_joined_rooms_for_user(user)

        for room_id in room_ids:
            self._room_serials[room_id] = self._user_cachemap_latest_serial
        if add_to_cache:
            statuscache = self._get_or_make_usercache(user)
        else:
            statuscache = self._get_or_offline_usercache(user)
        statuscache.update(state, serial=self._user_cachemap_latest_serial)
        defer.returnValue(statuscache)

    @defer.inlineCallbacks
    def push_update_to_local_and_remote(self, observed_user, statuscache,
                                        users_to_push=[], room_ids=[],
                                        remote_domains=[]):
        """Notify local clients and remote servers of a change in the presence
        of a user.

        Args:
            observed_user(UserID): The user to push the presence state for.
            statuscache(UserPresenceCache): The cache for the presence state to
                push.
            users_to_push([UserID]): A list of local and remote users to
                notify.
            room_ids([str]): Notify the local and remote occupants of these
                rooms.
            remote_domains([str]): A list of remote servers to notify in
                addition to those implied by the users_to_push and the
                room_ids.
        Returns:
            A Deferred.
        """

        localusers, remoteusers = partitionbool(
            users_to_push,
            lambda u: self.hs.is_mine(u)
        )

        localusers = set(localusers)

        self.push_update_to_clients(
            users_to_push=localusers, room_ids=room_ids
        )

        remote_domains = set(remote_domains)
        remote_domains |= set([r.domain for r in remoteusers])
        for room_id in room_ids:
            remote_domains.update(
                (yield self.store.get_joined_hosts_for_room(room_id))
            )

        remote_domains.discard(self.hs.hostname)

        deferreds = []
        for domain in remote_domains:
            logger.debug(" | push to remote domain %s", domain)
            deferreds.append(
                self._push_presence_remote(
                    observed_user, domain, state=statuscache.get_state()
                )
            )

        yield defer.DeferredList(deferreds, consumeErrors=True)

        defer.returnValue((localusers, remote_domains))

    def push_update_to_clients(self, users_to_push=[], room_ids=[]):
        """Notify clients of a new presence event.

        Args:
            users_to_push([UserID]): List of users to notify.
            room_ids([str]): List of room_ids to notify.
        """
        with PreserveLoggingContext():
            self.notifier.on_new_event(
                "presence_key",
                self._user_cachemap_latest_serial,
                users_to_push,
                room_ids,
            )

    @defer.inlineCallbacks
    def _push_presence_remote(self, user, destination, state=None):
        """Push a user's presence to a remote server. If a presence state event
        that event is sent. Otherwise a new state event is constructed from the
        stored presence state.
        The last_active is replaced with last_active_ago in case the wallclock
        time on the remote server is different to the time on this server.
        Sends an EDU to the remote server with the current presence state.

        Args:
            user(UserID): The user to push the presence state for.
            destination(str): The remote server to send state to.
            state(dict): The state to push, or None to use the current stored
                state.
        Returns:
            A Deferred.
        """
        if state is None:
            state = yield self.store.get_presence_state(user.localpart)
            del state["mtime"]
            state["presence"] = state.pop("state")

            if user in self._user_cachemap:
                state["last_active"] = (
                    self._user_cachemap[user].get_state()["last_active"]
                )

            yield collect_presencelike_data(self.distributor, user, state)

        if "last_active" in state:
            state = dict(state)
            state["last_active_ago"] = int(
                self.clock.time_msec() - state.pop("last_active")
            )

        user_state = {"user_id": user.to_string(), }
        user_state.update(state)

        yield self.federation.send_edu(
            destination=destination,
            edu_type="m.presence",
            content={"push": [user_state, ], }
        )


class PresenceEventSource(object):
    def __init__(self, hs):
        self.hs = hs
        self.clock = hs.get_clock()

    @defer.inlineCallbacks
    @log_function
    def get_new_events(self, user, from_key, room_ids=None, **kwargs):
        from_key = int(from_key)
        room_ids = room_ids or []

        presence = self.hs.get_handlers().presence_handler
        cachemap = presence._user_cachemap

        max_serial = presence._user_cachemap_latest_serial

        clock = self.clock
        latest_serial = 0

        user_ids_to_check = {user}
        presence_list = yield presence.store.get_presence_list(
            user.localpart, accepted=True
        )
        if presence_list is not None:
            user_ids_to_check |= set(
                UserID.from_string(p["observed_user_id"]) for p in presence_list
            )
        for room_id in set(room_ids) & set(presence._room_serials):
            if presence._room_serials[room_id] > from_key:
                joined = yield presence.get_joined_users_for_room_id(room_id)
                user_ids_to_check |= set(joined)

        updates = []
        for observed_user in user_ids_to_check & set(cachemap):
            cached = cachemap[observed_user]

            if cached.serial <= from_key or cached.serial > max_serial:
                continue

            latest_serial = max(cached.serial, latest_serial)
            updates.append(cached.make_event(user=observed_user, clock=clock))

        # TODO(paul): limit

        for serial, user_ids in presence._remote_offline_serials:
            if serial <= from_key:
                break

            if serial > max_serial:
                continue

            latest_serial = max(latest_serial, serial)
            for u in user_ids:
                updates.append({
                    "type": "m.presence",
                    "content": {"user_id": u, "presence": PresenceState.OFFLINE},
                })
        # TODO(paul): For the v2 API we want to tell the client their from_key
        #   is too old if we fell off the end of the _remote_offline_serials
        #   list, and get them to invalidate+resync. In v1 we have no such
        #   concept so this is a best-effort result.

        if updates:
            defer.returnValue((updates, latest_serial))
        else:
            defer.returnValue(([], presence._user_cachemap_latest_serial))

    def get_current_key(self):
        presence = self.hs.get_handlers().presence_handler
        return presence._user_cachemap_latest_serial

    @defer.inlineCallbacks
    def get_pagination_rows(self, user, pagination_config, key):
        # TODO (erikj): Does this make sense? Ordering?

        from_key = int(pagination_config.from_key)

        if pagination_config.to_key:
            to_key = int(pagination_config.to_key)
        else:
            to_key = -1

        presence = self.hs.get_handlers().presence_handler
        cachemap = presence._user_cachemap

        user_ids_to_check = {user}
        presence_list = yield presence.store.get_presence_list(
            user.localpart, accepted=True
        )
        if presence_list is not None:
            user_ids_to_check |= set(
                UserID.from_string(p["observed_user_id"]) for p in presence_list
            )
        room_ids = yield presence.get_joined_rooms_for_user(user)
        for room_id in set(room_ids) & set(presence._room_serials):
            if presence._room_serials[room_id] >= from_key:
                joined = yield presence.get_joined_users_for_room_id(room_id)
                user_ids_to_check |= set(joined)

        updates = []
        for observed_user in user_ids_to_check & set(cachemap):
            if not (to_key < cachemap[observed_user].serial <= from_key):
                continue

            updates.append((observed_user, cachemap[observed_user]))

        # TODO(paul): limit

        if updates:
            clock = self.clock

            earliest_serial = max([x[1].serial for x in updates])
            data = [x[1].make_event(user=x[0], clock=clock) for x in updates]

            defer.returnValue((data, earliest_serial))
        else:
            defer.returnValue(([], 0))


class UserPresenceCache(object):
    """Store an observed user's state and status message.

    Includes the update timestamp.
    """
    def __init__(self):
        self.state = {"presence": PresenceState.OFFLINE}
        self.serial = None

    def __repr__(self):
        return "UserPresenceCache(state=%r, serial=%r)" % (
            self.state, self.serial
        )

    def update(self, state, serial):
        assert("mtime_age" not in state)

        self.state.update(state)
        # Delete keys that are now 'None'
        for k in self.state.keys():
            if self.state[k] is None:
                del self.state[k]

        self.serial = serial

        if "status_msg" in state:
            self.status_msg = state["status_msg"]
        else:
            self.status_msg = None

    def get_state(self):
        # clone it so caller can't break our cache
        state = dict(self.state)
        return state

    def make_event(self, user, clock):
        content = self.get_state()
        content["user_id"] = user.to_string()

        if "last_active" in content:
            content["last_active_ago"] = int(
                clock.time_msec() - content.pop("last_active")
            )

        return {"type": "m.presence", "content": content}
