# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
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

from synapse.util.logutils import log_function
from synapse.util.logcontext import PreserveLoggingContext
from synapse.types import UserID

from ._base import BaseHandler

import logging


logger = logging.getLogger(__name__)


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

        # map any user to a UserPresenceCache
        self._user_cachemap = {}
        self._user_cachemap_latest_serial = 0

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
    def get_state(self, target_user, auth_user, as_event=False):
        if self.hs.is_mine(target_user):
            visible = yield self.is_presence_visible(
                observer_user=auth_user,
                observed_user=target_user
            )

            if not visible:
                raise SynapseError(404, "Presence information not visible")
            state = yield self.store.get_presence_state(target_user.localpart)
            if "mtime" in state:
                del state["mtime"]
            state["presence"] = state.pop("state")

            if target_user in self._user_cachemap:
                cached_state = self._user_cachemap[target_user].get_state()
                if "last_active" in cached_state:
                    state["last_active"] = cached_state["last_active"]
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
        yield self.distributor.fire(
            "collect_presencelike_data", target_user, state
        )

        if now_level > was_level:
            state["last_active"] = self.clock.time_msec()

        now_online = state["presence"] != PresenceState.OFFLINE
        was_polling = target_user in self._user_cachemap

        with PreserveLoggingContext():
            if now_online and not was_polling:
                self.start_polling_presence(target_user, state=state)
            elif not now_online and was_polling:
                self.stop_polling_presence(target_user)

            # TODO(paul): perform a presence push as part of start/stop poll so
            #   we don't have to do this all the time
            self.changed_presencelike_data(target_user, state)

    def bump_presence_active_time(self, user, now=None):
        if now is None:
            now = self.clock.time_msec()

        self.changed_presencelike_data(user, {"last_active": now})

    def changed_presencelike_data(self, user, state):
        statuscache = self._get_or_make_usercache(user)

        self._user_cachemap_latest_serial += 1
        statuscache.update(state, serial=self._user_cachemap_latest_serial)

        return self.push_presence(user, statuscache=statuscache)

    @log_function
    def started_user_eventstream(self, user):
        # TODO(paul): Use "last online" state
        self.set_state(user, user, {"presence": PresenceState.ONLINE})

    @log_function
    def stopped_user_eventstream(self, user):
        # TODO(paul): Save current state as "last online" state
        self.set_state(user, user, {"presence": PresenceState.OFFLINE})

    @defer.inlineCallbacks
    def user_joined_room(self, user, room_id):
        if self.hs.is_mine(user):
            statuscache = self._get_or_make_usercache(user)

            # No actual update but we need to bump the serial anyway for the
            # event source
            self._user_cachemap_latest_serial += 1
            statuscache.update({}, serial=self._user_cachemap_latest_serial)

            self.push_update_to_local_and_remote(
                observed_user=user,
                room_ids=[room_id],
                statuscache=statuscache,
            )

        # We also want to tell them about current presence of people.
        rm_handler = self.homeserver.get_handlers().room_member_handler
        curr_users = yield rm_handler.get_room_members(room_id)

        for local_user in [c for c in curr_users if self.hs.is_mine(c)]:
            self.push_update_to_local_and_remote(
                observed_user=local_user,
                users_to_push=[user],
                statuscache=self._get_or_offline_usercache(local_user),
            )

    @defer.inlineCallbacks
    def send_invite(self, observer_user, observed_user):
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
        yield self.store.set_presence_list_accepted(
            observer_user.localpart, observed_user.to_string()
        )
        with PreserveLoggingContext():
            self.start_polling_presence(
                observer_user, target_user=observed_user
            )

    @defer.inlineCallbacks
    def deny_presence(self, observed_user, observer_user):
        yield self.store.del_presence_list(
            observer_user.localpart, observed_user.to_string()
        )

        # TODO(paul): Inform the user somehow?

    @defer.inlineCallbacks
    def drop(self, observed_user, observer_user):
        if not self.hs.is_mine(observer_user):
            raise SynapseError(400, "User is not hosted on this Home Server")

        yield self.store.del_presence_list(
            observer_user.localpart, observed_user.to_string()
        )

        with PreserveLoggingContext():
            self.stop_polling_presence(
                observer_user, target_user=observed_user
            )

    @defer.inlineCallbacks
    def get_presence_list(self, observer_user, accepted=None):
        if not self.hs.is_mine(observer_user):
            raise SynapseError(400, "User is not hosted on this Home Server")

        presence = yield self.store.get_presence_list(
            observer_user.localpart, accepted=accepted
        )

        for p in presence:
            observed_user = UserID.from_string(p.pop("observed_user_id"))
            p["observed_user"] = observed_user
            p.update(self._get_or_offline_usercache(observed_user).get_state())
            if "last_active" in p:
                p["last_active_ago"] = int(
                    self.clock.time_msec() - p.pop("last_active")
                )

        defer.returnValue(presence)

    @defer.inlineCallbacks
    @log_function
    def start_polling_presence(self, user, target_user=None, state=None):
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

            rm_handler = self.homeserver.get_handlers().room_member_handler
            room_ids = yield rm_handler.get_rooms_for_user(user)

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
                    observed_user=target_user,
                    users_to_push=[user],
                    statuscache=self._get_or_offline_usercache(target_user),
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
        target_localpart = target_user.localpart

        if target_localpart not in self._local_pushmap:
            self._local_pushmap[target_localpart] = set()

        self._local_pushmap[target_localpart].add(user)

    def _start_polling_remote(self, user, domain, remoteusers):
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
        for localpart in self._local_pushmap.keys():
            if target_user and localpart != target_user.localpart:
                continue

            if user in self._local_pushmap[localpart]:
                self._local_pushmap[localpart].remove(user)

            if not self._local_pushmap[localpart]:
                del self._local_pushmap[localpart]

    @log_function
    def _stop_polling_remote(self, user, domain, remoteusers):
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
        assert(self.hs.is_mine(user))

        logger.debug("Pushing presence update from %s", user)

        localusers = set(self._local_pushmap.get(user.localpart, set()))
        remotedomains = set(self._remote_sendmap.get(user.localpart, set()))

        # Reflect users' status changes back to themselves, so UIs look nice
        # and also user is informed of server-forced pushes
        localusers.add(user)

        rm_handler = self.homeserver.get_handlers().room_member_handler
        room_ids = yield rm_handler.get_rooms_for_user(user)

        if not localusers and not room_ids:
            defer.returnValue(None)

        yield self.push_update_to_local_and_remote(
            observed_user=user,
            users_to_push=localusers,
            remote_domains=remotedomains,
            room_ids=room_ids,
            statuscache=statuscache,
        )
        yield self.distributor.fire("user_presence_changed", user, statuscache)

    @defer.inlineCallbacks
    def _push_presence_remote(self, user, destination, state=None):
        if state is None:
            state = yield self.store.get_presence_state(user.localpart)
            del state["mtime"]
            state["presence"] = state.pop("state")

            if user in self._user_cachemap:
                state["last_active"] = (
                    self._user_cachemap[user].get_state()["last_active"]
                )

            yield self.distributor.fire(
                "collect_presencelike_data", user, state
            )

        if "last_active" in state:
            state = dict(state)
            state["last_active_ago"] = int(
                self.clock.time_msec() - state.pop("last_active")
            )

        user_state = {
            "user_id": user.to_string(),
        }
        user_state.update(**state)

        yield self.federation.send_edu(
            destination=destination,
            edu_type="m.presence",
            content={
                "push": [
                    user_state,
                ],
            }
        )

    @defer.inlineCallbacks
    def incoming_presence(self, origin, content):
        deferreds = []

        for push in content.get("push", []):
            user = UserID.from_string(push["user_id"])

            logger.debug("Incoming presence update from %s", user)

            observers = set(self._remote_recvmap.get(user, set()))
            if observers:
                logger.debug(
                    " | %d interested local observers %r", len(observers), observers
                )

            rm_handler = self.homeserver.get_handlers().room_member_handler
            room_ids = yield rm_handler.get_rooms_for_user(user)
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

            statuscache = self._get_or_make_usercache(user)

            self._user_cachemap_latest_serial += 1
            statuscache.update(state, serial=self._user_cachemap_latest_serial)

            if not observers and not room_ids:
                logger.debug(" | no interested observers or room IDs")
                continue

            self.push_update_to_clients(
                observed_user=user,
                users_to_push=observers,
                room_ids=room_ids,
                statuscache=statuscache,
            )

            if state["presence"] == PresenceState.OFFLINE:
                del self._user_cachemap[user]

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

        with PreserveLoggingContext():
            yield defer.DeferredList(deferreds, consumeErrors=True)

    @defer.inlineCallbacks
    def push_update_to_local_and_remote(self, observed_user, statuscache,
                                        users_to_push=[], room_ids=[],
                                        remote_domains=[]):

        localusers, remoteusers = partitionbool(
            users_to_push,
            lambda u: self.hs.is_mine(u)
        )

        localusers = set(localusers)

        self.push_update_to_clients(
            observed_user=observed_user,
            users_to_push=localusers,
            room_ids=room_ids,
            statuscache=statuscache,
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

    def push_update_to_clients(self, observed_user, users_to_push=[],
                               room_ids=[], statuscache=None):
        self.notifier.on_new_user_event(
            users_to_push,
            room_ids,
        )


class PresenceEventSource(object):
    def __init__(self, hs):
        self.hs = hs
        self.clock = hs.get_clock()

    @defer.inlineCallbacks
    def is_visible(self, observer_user, observed_user):
        if observer_user == observed_user:
            defer.returnValue(True)

        presence = self.hs.get_handlers().presence_handler

        if (yield presence.store.user_rooms_intersect(
                [u.to_string() for u in observer_user, observed_user])):
            defer.returnValue(True)

        if self.hs.is_mine(observed_user):
            pushmap = presence._local_pushmap

            defer.returnValue(
                observed_user.localpart in pushmap and
                observer_user in pushmap[observed_user.localpart]
            )
        else:
            recvmap = presence._remote_recvmap

            defer.returnValue(
                observed_user in recvmap and
                observer_user in recvmap[observed_user]
            )

    @defer.inlineCallbacks
    @log_function
    def get_new_events_for_user(self, user, from_key, limit):
        from_key = int(from_key)

        observer_user = user

        presence = self.hs.get_handlers().presence_handler
        cachemap = presence._user_cachemap

        updates = []
        # TODO(paul): use a DeferredList ? How to limit concurrency.
        for observed_user in cachemap.keys():
            cached = cachemap[observed_user]

            if cached.serial <= from_key:
                continue

            if (yield self.is_visible(observer_user, observed_user)):
                updates.append((observed_user, cached))

        # TODO(paul): limit

        if updates:
            clock = self.clock

            latest_serial = max([x[1].serial for x in updates])
            data = [x[1].make_event(user=x[0], clock=clock) for x in updates]

            defer.returnValue((data, latest_serial))
        else:
            defer.returnValue(([], presence._user_cachemap_latest_serial))

    def get_current_key(self):
        presence = self.hs.get_handlers().presence_handler
        return presence._user_cachemap_latest_serial

    @defer.inlineCallbacks
    def get_pagination_rows(self, user, pagination_config, key):
        # TODO (erikj): Does this make sense? Ordering?

        observer_user = user

        from_key = int(pagination_config.from_key)

        if pagination_config.to_key:
            to_key = int(pagination_config.to_key)
        else:
            to_key = -1

        presence = self.hs.get_handlers().presence_handler
        cachemap = presence._user_cachemap

        updates = []
        # TODO(paul): use a DeferredList ? How to limit concurrency.
        for observed_user in cachemap.keys():
            if not (to_key < cachemap[observed_user].serial <= from_key):
                continue

            if (yield self.is_visible(observer_user, observed_user)):
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
