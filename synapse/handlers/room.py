# -*- coding: utf-8 -*-
# Copyright 2014 - 2016 OpenMarket Ltd
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

"""Contains functions for performing events on rooms."""
from twisted.internet import defer

from ._base import BaseHandler

from synapse.types import UserID, RoomAlias, RoomID, RoomStreamToken
from synapse.api.constants import (
    EventTypes, JoinRules, RoomCreationPreset, Membership,
)
from synapse.api.errors import AuthError, StoreError, SynapseError
from synapse.util import stringutils
from synapse.util.async import concurrently_execute
from synapse.util.caches.response_cache import ResponseCache
from synapse.visibility import filter_events_for_client

from collections import OrderedDict

import logging
import math
import string

logger = logging.getLogger(__name__)

REMOTE_ROOM_LIST_POLL_INTERVAL = 60 * 1000

id_server_scheme = "https://"


class RoomCreationHandler(BaseHandler):

    PRESETS_DICT = {
        RoomCreationPreset.PRIVATE_CHAT: {
            "join_rules": JoinRules.INVITE,
            "history_visibility": "shared",
            "original_invitees_have_ops": False,
        },
        RoomCreationPreset.TRUSTED_PRIVATE_CHAT: {
            "join_rules": JoinRules.INVITE,
            "history_visibility": "shared",
            "original_invitees_have_ops": True,
        },
        RoomCreationPreset.PUBLIC_CHAT: {
            "join_rules": JoinRules.PUBLIC,
            "history_visibility": "shared",
            "original_invitees_have_ops": False,
        },
    }

    @defer.inlineCallbacks
    def create_room(self, requester, config):
        """ Creates a new room.

        Args:
            requester (Requester): The user who requested the room creation.
            config (dict) : A dict of configuration options.
        Returns:
            The new room ID.
        Raises:
            SynapseError if the room ID couldn't be stored, or something went
            horribly wrong.
        """
        user_id = requester.user.to_string()

        self.ratelimit(requester)

        if "room_alias_name" in config:
            for wchar in string.whitespace:
                if wchar in config["room_alias_name"]:
                    raise SynapseError(400, "Invalid characters in room alias")

            room_alias = RoomAlias.create(
                config["room_alias_name"],
                self.hs.hostname,
            )
            mapping = yield self.store.get_association_from_room_alias(
                room_alias
            )

            if mapping:
                raise SynapseError(400, "Room alias already taken")
        else:
            room_alias = None

        invite_list = config.get("invite", [])
        for i in invite_list:
            try:
                UserID.from_string(i)
            except:
                raise SynapseError(400, "Invalid user_id: %s" % (i,))

        invite_3pid_list = config.get("invite_3pid", [])

        visibility = config.get("visibility", None)
        is_public = visibility == "public"

        # autogen room IDs and try to create it. We may clash, so just
        # try a few times till one goes through, giving up eventually.
        attempts = 0
        room_id = None
        while attempts < 5:
            try:
                random_string = stringutils.random_string(18)
                gen_room_id = RoomID.create(
                    random_string,
                    self.hs.hostname,
                )
                yield self.store.store_room(
                    room_id=gen_room_id.to_string(),
                    room_creator_user_id=user_id,
                    is_public=is_public
                )
                room_id = gen_room_id.to_string()
                break
            except StoreError:
                attempts += 1
        if not room_id:
            raise StoreError(500, "Couldn't generate a room ID.")

        if room_alias:
            directory_handler = self.hs.get_handlers().directory_handler
            yield directory_handler.create_association(
                user_id=user_id,
                room_id=room_id,
                room_alias=room_alias,
                servers=[self.hs.hostname],
            )

        preset_config = config.get(
            "preset",
            RoomCreationPreset.PRIVATE_CHAT
            if visibility == "private"
            else RoomCreationPreset.PUBLIC_CHAT
        )

        raw_initial_state = config.get("initial_state", [])

        initial_state = OrderedDict()
        for val in raw_initial_state:
            initial_state[(val["type"], val.get("state_key", ""))] = val["content"]

        creation_content = config.get("creation_content", {})

        msg_handler = self.hs.get_handlers().message_handler
        room_member_handler = self.hs.get_handlers().room_member_handler

        yield self._send_events_for_new_room(
            requester,
            room_id,
            msg_handler,
            room_member_handler,
            preset_config=preset_config,
            invite_list=invite_list,
            initial_state=initial_state,
            creation_content=creation_content,
            room_alias=room_alias,
        )

        if "name" in config:
            name = config["name"]
            yield msg_handler.create_and_send_nonmember_event(
                requester,
                {
                    "type": EventTypes.Name,
                    "room_id": room_id,
                    "sender": user_id,
                    "state_key": "",
                    "content": {"name": name},
                },
                ratelimit=False)

        if "topic" in config:
            topic = config["topic"]
            yield msg_handler.create_and_send_nonmember_event(
                requester,
                {
                    "type": EventTypes.Topic,
                    "room_id": room_id,
                    "sender": user_id,
                    "state_key": "",
                    "content": {"topic": topic},
                },
                ratelimit=False)

        for invitee in invite_list:
            yield room_member_handler.update_membership(
                requester,
                UserID.from_string(invitee),
                room_id,
                "invite",
                ratelimit=False,
            )

        for invite_3pid in invite_3pid_list:
            id_server = invite_3pid["id_server"]
            address = invite_3pid["address"]
            medium = invite_3pid["medium"]
            yield self.hs.get_handlers().room_member_handler.do_3pid_invite(
                room_id,
                requester.user,
                medium,
                address,
                id_server,
                requester,
                txn_id=None,
            )

        result = {"room_id": room_id}

        if room_alias:
            result["room_alias"] = room_alias.to_string()
            yield directory_handler.send_room_alias_update_event(
                requester, user_id, room_id
            )

        defer.returnValue(result)

    @defer.inlineCallbacks
    def _send_events_for_new_room(
            self,
            creator,  # A Requester object.
            room_id,
            msg_handler,
            room_member_handler,
            preset_config,
            invite_list,
            initial_state,
            creation_content,
            room_alias
    ):
        def create(etype, content, **kwargs):
            e = {
                "type": etype,
                "content": content,
            }

            e.update(event_keys)
            e.update(kwargs)

            return e

        @defer.inlineCallbacks
        def send(etype, content, **kwargs):
            event = create(etype, content, **kwargs)
            yield msg_handler.create_and_send_nonmember_event(
                creator,
                event,
                ratelimit=False
            )

        config = RoomCreationHandler.PRESETS_DICT[preset_config]

        creator_id = creator.user.to_string()

        event_keys = {
            "room_id": room_id,
            "sender": creator_id,
            "state_key": "",
        }

        creation_content.update({"creator": creator_id})
        yield send(
            etype=EventTypes.Create,
            content=creation_content,
        )

        yield room_member_handler.update_membership(
            creator,
            creator.user,
            room_id,
            "join",
            ratelimit=False,
        )

        if (EventTypes.PowerLevels, '') not in initial_state:
            power_level_content = {
                "users": {
                    creator_id: 100,
                },
                "users_default": 0,
                "events": {
                    EventTypes.Name: 50,
                    EventTypes.PowerLevels: 100,
                    EventTypes.RoomHistoryVisibility: 100,
                    EventTypes.CanonicalAlias: 50,
                    EventTypes.RoomAvatar: 50,
                },
                "events_default": 0,
                "state_default": 50,
                "ban": 50,
                "kick": 50,
                "redact": 50,
                "invite": 0,
            }

            if config["original_invitees_have_ops"]:
                for invitee in invite_list:
                    power_level_content["users"][invitee] = 100

            yield send(
                etype=EventTypes.PowerLevels,
                content=power_level_content,
            )

        if room_alias and (EventTypes.CanonicalAlias, '') not in initial_state:
            yield send(
                etype=EventTypes.CanonicalAlias,
                content={"alias": room_alias.to_string()},
            )

        if (EventTypes.JoinRules, '') not in initial_state:
            yield send(
                etype=EventTypes.JoinRules,
                content={"join_rule": config["join_rules"]},
            )

        if (EventTypes.RoomHistoryVisibility, '') not in initial_state:
            yield send(
                etype=EventTypes.RoomHistoryVisibility,
                content={"history_visibility": config["history_visibility"]}
            )

        for (etype, state_key), content in initial_state.items():
            yield send(
                etype=etype,
                state_key=state_key,
                content=content,
            )


class RoomListHandler(BaseHandler):
    def __init__(self, hs):
        super(RoomListHandler, self).__init__(hs)
        self.response_cache = ResponseCache(hs)
        self.remote_list_request_cache = ResponseCache(hs)
        self.remote_list_cache = {}
        self.fetch_looping_call = hs.get_clock().looping_call(
            self.fetch_all_remote_lists, REMOTE_ROOM_LIST_POLL_INTERVAL
        )
        self.fetch_all_remote_lists()

    def get_local_public_room_list(self):
        result = self.response_cache.get(())
        if not result:
            result = self.response_cache.set((), self._get_public_room_list())
        return result

    @defer.inlineCallbacks
    def _get_public_room_list(self):
        room_ids = yield self.store.get_public_room_ids()

        results = []

        @defer.inlineCallbacks
        def handle_room(room_id):
            current_state = yield self.state_handler.get_current_state(room_id)

            # Double check that this is actually a public room.
            join_rules_event = current_state.get((EventTypes.JoinRules, ""))
            if join_rules_event:
                join_rule = join_rules_event.content.get("join_rule", None)
                if join_rule and join_rule != JoinRules.PUBLIC:
                    defer.returnValue(None)

            result = {"room_id": room_id}

            num_joined_users = len([
                1 for _, event in current_state.items()
                if event.type == EventTypes.Member
                and event.membership == Membership.JOIN
            ])
            if num_joined_users == 0:
                return

            result["num_joined_members"] = num_joined_users

            aliases = yield self.store.get_aliases_for_room(room_id)
            if aliases:
                result["aliases"] = aliases

            name_event = yield current_state.get((EventTypes.Name, ""))
            if name_event:
                name = name_event.content.get("name", None)
                if name:
                    result["name"] = name

            topic_event = current_state.get((EventTypes.Topic, ""))
            if topic_event:
                topic = topic_event.content.get("topic", None)
                if topic:
                    result["topic"] = topic

            canonical_event = current_state.get((EventTypes.CanonicalAlias, ""))
            if canonical_event:
                canonical_alias = canonical_event.content.get("alias", None)
                if canonical_alias:
                    result["canonical_alias"] = canonical_alias

            visibility_event = current_state.get((EventTypes.RoomHistoryVisibility, ""))
            visibility = None
            if visibility_event:
                visibility = visibility_event.content.get("history_visibility", None)
            result["world_readable"] = visibility == "world_readable"

            guest_event = current_state.get((EventTypes.GuestAccess, ""))
            guest = None
            if guest_event:
                guest = guest_event.content.get("guest_access", None)
            result["guest_can_join"] = guest == "can_join"

            avatar_event = current_state.get(("m.room.avatar", ""))
            if avatar_event:
                avatar_url = avatar_event.content.get("url", None)
                if avatar_url:
                    result["avatar_url"] = avatar_url

            results.append(result)

        yield concurrently_execute(handle_room, room_ids, 10)

        # FIXME (erikj): START is no longer a valid value
        defer.returnValue({"start": "START", "end": "END", "chunk": results})

    @defer.inlineCallbacks
    def fetch_all_remote_lists(self):
        deferred = self.hs.get_replication_layer().get_public_rooms(
            self.hs.config.secondary_directory_servers
        )
        self.remote_list_request_cache.set((), deferred)
        self.remote_list_cache = yield deferred

    @defer.inlineCallbacks
    def get_aggregated_public_room_list(self):
        """
        Get the public room list from this server and the servers
        specified in the secondary_directory_servers config option.
        XXX: Pagination...
        """
        # We return the results from out cache which is updated by a looping call,
        # unless we're missing a cache entry, in which case wait for the result
        # of the fetch if there's one in progress. If not, omit that server.
        wait = False
        for s in self.hs.config.secondary_directory_servers:
            if s not in self.remote_list_cache:
                logger.warn("No cached room list from %s: waiting for fetch", s)
                wait = True
                break

        if wait and self.remote_list_request_cache.get(()):
            yield self.remote_list_request_cache.get(())

        public_rooms = yield self.get_local_public_room_list()

        # keep track of which room IDs we've seen so we can de-dup
        room_ids = set()

        # tag all the ones in our list with our server name.
        # Also add the them to the de-deping set
        for room in public_rooms['chunk']:
            room["server_name"] = self.hs.hostname
            room_ids.add(room["room_id"])

        # Now add the results from federation
        for server_name, server_result in self.remote_list_cache.items():
            for room in server_result["chunk"]:
                if room["room_id"] not in room_ids:
                    room["server_name"] = server_name
                    public_rooms["chunk"].append(room)
                    room_ids.add(room["room_id"])

        defer.returnValue(public_rooms)


class RoomContextHandler(BaseHandler):
    @defer.inlineCallbacks
    def get_event_context(self, user, room_id, event_id, limit, is_guest):
        """Retrieves events, pagination tokens and state around a given event
        in a room.

        Args:
            user (UserID)
            room_id (str)
            event_id (str)
            limit (int): The maximum number of events to return in total
                (excluding state).

        Returns:
            dict, or None if the event isn't found
        """
        before_limit = math.floor(limit / 2.)
        after_limit = limit - before_limit

        now_token = yield self.hs.get_event_sources().get_current_token()

        def filter_evts(events):
            return filter_events_for_client(
                self.store,
                user.to_string(),
                events,
                is_peeking=is_guest
            )

        event = yield self.store.get_event(event_id, get_prev_content=True,
                                           allow_none=True)
        if not event:
            defer.returnValue(None)
            return

        filtered = yield(filter_evts([event]))
        if not filtered:
            raise AuthError(
                403,
                "You don't have permission to access that event."
            )

        results = yield self.store.get_events_around(
            room_id, event_id, before_limit, after_limit
        )

        results["events_before"] = yield filter_evts(results["events_before"])
        results["events_after"] = yield filter_evts(results["events_after"])
        results["event"] = event

        if results["events_after"]:
            last_event_id = results["events_after"][-1].event_id
        else:
            last_event_id = event_id

        state = yield self.store.get_state_for_events(
            [last_event_id], None
        )
        results["state"] = state[last_event_id].values()

        results["start"] = now_token.copy_and_replace(
            "room_key", results["start"]
        ).to_string()

        results["end"] = now_token.copy_and_replace(
            "room_key", results["end"]
        ).to_string()

        defer.returnValue(results)


class RoomEventSource(object):
    def __init__(self, hs):
        self.store = hs.get_datastore()

    @defer.inlineCallbacks
    def get_new_events(
            self,
            user,
            from_key,
            limit,
            room_ids,
            is_guest,
    ):
        # We just ignore the key for now.

        to_key = yield self.get_current_key()

        from_token = RoomStreamToken.parse(from_key)
        if from_token.topological:
            logger.warn("Stream has topological part!!!! %r", from_key)
            from_key = "s%s" % (from_token.stream,)

        app_service = yield self.store.get_app_service_by_user_id(
            user.to_string()
        )
        if app_service:
            events, end_key = yield self.store.get_appservice_room_stream(
                service=app_service,
                from_key=from_key,
                to_key=to_key,
                limit=limit,
            )
        else:
            room_events = yield self.store.get_membership_changes_for_user(
                user.to_string(), from_key, to_key
            )

            room_to_events = yield self.store.get_room_events_stream_for_rooms(
                room_ids=room_ids,
                from_key=from_key,
                to_key=to_key,
                limit=limit or 10,
                order='ASC',
            )

            events = list(room_events)
            events.extend(e for evs, _ in room_to_events.values() for e in evs)

            events.sort(key=lambda e: e.internal_metadata.order)

            if limit:
                events[:] = events[:limit]

            if events:
                end_key = events[-1].internal_metadata.after
            else:
                end_key = to_key

        defer.returnValue((events, end_key))

    def get_current_key(self, direction='f'):
        return self.store.get_room_events_max_id(direction)

    @defer.inlineCallbacks
    def get_pagination_rows(self, user, config, key):
        events, next_key = yield self.store.paginate_room_events(
            room_id=key,
            from_key=config.from_key,
            to_key=config.to_key,
            direction=config.direction,
            limit=config.limit,
        )

        defer.returnValue((events, next_key))
