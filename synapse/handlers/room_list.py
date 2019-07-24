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

import logging
from collections import namedtuple

from six import PY3, iteritems

import msgpack
from unpaddedbase64 import decode_base64, encode_base64

from twisted.internet import defer

from synapse.api.constants import EventTypes, JoinRules
from synapse.api.errors import Codes, HttpResponseException
from synapse.types import ThirdPartyInstanceID
from synapse.util.caches.descriptors import cachedInlineCallbacks
from synapse.util.caches.response_cache import ResponseCache

from ._base import BaseHandler

logger = logging.getLogger(__name__)

REMOTE_ROOM_LIST_POLL_INTERVAL = 60 * 1000

# This is used to indicate we should only return rooms published to the main list.
EMPTY_THIRD_PARTY_ID = ThirdPartyInstanceID(None, None)


class RoomListHandler(BaseHandler):
    def __init__(self, hs):
        super(RoomListHandler, self).__init__(hs)
        self.enable_room_list_search = hs.config.enable_room_list_search
        self.response_cache = ResponseCache(hs, "room_list")
        self.remote_response_cache = ResponseCache(
            hs, "remote_room_list", timeout_ms=30 * 1000
        )

    def get_local_public_room_list(
        self,
        limit=None,
        since_token=None,
        search_filter=None,
        network_tuple=EMPTY_THIRD_PARTY_ID,
        from_federation=False,
    ):
        """Generate a local public room list.

        There are multiple different lists: the main one plus one per third
        party network. A client can ask for a specific list or to return all.

        Args:
            limit (int|None)
            since_token (str|None)
            search_filter (dict|None)
            network_tuple (ThirdPartyInstanceID): Which public list to use.
                This can be (None, None) to indicate the main list, or a particular
                appservice and network id to use an appservice specific one.
                Setting to None returns all public rooms across all lists.
            from_federation (bool): true iff the request comes from the federation
                API
        """
        if not self.enable_room_list_search:
            return defer.succeed({"chunk": [], "total_room_count_estimate": 0})

        logger.info(
            "Getting public room list: limit=%r, since=%r, search=%r, network=%r",
            limit,
            since_token,
            bool(search_filter),
            network_tuple,
        )

        if search_filter:
            # We explicitly don't bother caching searches or requests for
            # appservice specific lists.
            logger.info("Bypassing cache as search request.")

            # XXX: Quick hack to stop room directory queries taking too long.
            # Timeout request after 60s. Probably want a more fundamental
            # solution at some point
            timeout = self.clock.time() + 60
            return self._get_public_room_list(
                limit,
                since_token,
                search_filter,
                network_tuple=network_tuple,
                timeout=timeout,
            )

        key = (limit, since_token, network_tuple)
        return self.response_cache.wrap(
            key,
            self._get_public_room_list,
            limit,
            since_token,
            network_tuple=network_tuple,
            from_federation=from_federation,
        )

    @defer.inlineCallbacks
    def _get_public_room_list(
        self,
        limit=None,
        since_token=None,
        search_filter=None,
        network_tuple=EMPTY_THIRD_PARTY_ID,
        from_federation=False,
        timeout=None,
    ):
        """Generate a public room list.
        Args:
            limit (int|None): Maximum amount of rooms to return.
            since_token (str|None)
            search_filter (dict|None): Dictionary to filter rooms by.
            network_tuple (ThirdPartyInstanceID): Which public list to use.
                This can be (None, None) to indicate the main list, or a particular
                appservice and network id to use an appservice specific one.
                Setting to None returns all public rooms across all lists.
            from_federation (bool): Whether this request originated from a
                federating server or a client. Used for room filtering.
            timeout (int|None): Amount of seconds to wait for a response before
                timing out. TODO
        """
        pagination_token = None
        if since_token and since_token != "END":  # todo ought we support END and START?
            if since_token[0] in ("+", "-"):
                forwards = since_token[0] == "+"
                pagination_token = since_token[1:]
            else:
                raise SyntaxError("shrug ")  # TODO
        else:
            forwards = True

        # we request one more than wanted to see if there are more pages to come
        probing_limit = limit + 1 if limit is not None else None

        results = yield self.store.get_largest_public_rooms(
            network_tuple,
            search_filter,
            probing_limit,
            pagination_token,
            forwards,
            fetch_creation_event_ids=from_federation,
        )

        def build_room_entry(room):
            entry = {
                "room_id": room["room_id"],
                "name": room["name"],
                "topic": room["topic"],
                "canonical_alias": room["canonical_alias"],
                "num_joined_members": room["joined_members"],
                "avatar_url": room["avatar"],
                "world_readable": room["history_visibility"] == "world_readable",
            }

            # Filter out Nones – rather omit the field altogether
            return {k: v for k, v in entry.items() if v is not None}

        if from_federation:
            room_creation_event_ids = [r["creation_event_id"] for r in results]

        results = [build_room_entry(r) for r in results]

        response = {}
        num_results = len(results)
        if num_results > 0:
            final_room_id = results[-1]["room_id"]
            initial_room_id = results[0]["room_id"]
            if limit is not None:
                more_to_come = num_results == probing_limit
                results = results[0:limit]
            else:
                more_to_come = False

            if not forwards or (forwards and more_to_come):
                response["next_batch"] = "+%s" % (final_room_id,)

            if since_token and (forwards or (not forwards and more_to_come)):
                if num_results > 0:
                    response["prev_batch"] = "-%s" % (initial_room_id,)
                else:
                    response["prev_batch"] = "-%s" % (pagination_token,)

        if from_federation:
            # only show rooms with m.federate=True or absent (default is True)

            # we already have rooms' creation state events' IDs
            # so get rooms' creation state events
            creation_events_by_id = yield self.store.get_events(room_creation_event_ids)

            # now filter out rooms with m.federate: False in their create event
            results = [
                room
                for (room, room_creation_event_id) in zip(
                    results, room_creation_event_ids
                )
                if creation_events_by_id[room_creation_event_id].content.get(
                    "m.federate", True
                )
            ]

        for room in results:
            # populate search result entries with additional fields, namely
            # 'aliases' and 'guest_can_join'
            room_id = room["room_id"]

            aliases = yield self.store.get_aliases_for_room(room_id)
            if aliases:
                room["aliases"] = aliases

            state_ids = yield self.store.get_current_state_ids(room_id)
            guests_can_join = False
            guest_access_state_id = state_ids.get((EventTypes.GuestAccess, ""))
            if guest_access_state_id is not None:
                guest_access = yield self.store.get_event(guest_access_state_id)
                if guest_access is not None:
                    if guest_access.content.get("guest_access") == "can_join":
                        guests_can_join = True
            room["guest_can_join"] = guests_can_join

        response["chunk"] = results

        # TODO for federation, we currently don't remove m.federate=False rooms
        #   from the total room count estimate.
        response["total_room_count_estimate"] = yield self.store.count_public_rooms()

        return response

    @defer.inlineCallbacks
    def _append_room_entry_to_chunk(
        self,
        room_id,
        num_joined_users,
        chunk,
        limit,
        search_filter,
        from_federation=False,
    ):
        """Generate the entry for a room in the public room list and append it
        to the `chunk` if it matches the search filter

        Args:
            room_id (str): The ID of the room.
            num_joined_users (int): The number of joined users in the room.
            chunk (list)
            limit (int|None): Maximum amount of rooms to display. Function will
                return if length of chunk is greater than limit + 1.
            search_filter (dict|None)
            from_federation (bool): Whether this request originated from a
                federating server or a client. Used for room filtering.
        """
        if limit and len(chunk) > limit + 1:
            # We've already got enough, so lets just drop it.
            return

        result = yield self.generate_room_entry(room_id, num_joined_users)
        if not result:
            return

        if from_federation and not result.get("m.federate", True):
            # This is a room that other servers cannot join. Do not show them
            # this room.
            return

        if _matches_room_entry(result, search_filter):
            chunk.append(result)

    @cachedInlineCallbacks(num_args=1, cache_context=True)
    def generate_room_entry(
        self,
        room_id,
        num_joined_users,
        cache_context,
        with_alias=True,
        allow_private=False,
    ):
        """Returns the entry for a room

        Args:
            room_id (str): The room's ID.
            num_joined_users (int): Number of users in the room.
            cache_context: Information for cached responses.
            with_alias (bool): Whether to return the room's aliases in the result.
            allow_private (bool): Whether invite-only rooms should be shown.

        Returns:
            Deferred[dict|None]: Returns a room entry as a dictionary, or None if this
            room was determined not to be shown publicly.
        """
        result = {"room_id": room_id, "num_joined_members": num_joined_users}

        current_state_ids = yield self.store.get_current_state_ids(
            room_id, on_invalidate=cache_context.invalidate
        )

        event_map = yield self.store.get_events(
            [
                event_id
                for key, event_id in iteritems(current_state_ids)
                if key[0]
                in (
                    EventTypes.Create,
                    EventTypes.JoinRules,
                    EventTypes.Name,
                    EventTypes.Topic,
                    EventTypes.CanonicalAlias,
                    EventTypes.RoomHistoryVisibility,
                    EventTypes.GuestAccess,
                    "m.room.avatar",
                )
            ]
        )

        current_state = {(ev.type, ev.state_key): ev for ev in event_map.values()}

        # Double check that this is actually a public room.

        join_rules_event = current_state.get((EventTypes.JoinRules, ""))
        if join_rules_event:
            join_rule = join_rules_event.content.get("join_rule", None)
            if not allow_private and join_rule and join_rule != JoinRules.PUBLIC:
                return None

        # Return whether this room is open to federation users or not
        create_event = current_state.get((EventTypes.Create, ""))
        result["m.federate"] = create_event.content.get("m.federate", True)

        if with_alias:
            aliases = yield self.store.get_aliases_for_room(
                room_id, on_invalidate=cache_context.invalidate
            )
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

        return result

    @defer.inlineCallbacks
    def get_remote_public_room_list(
        self,
        server_name,
        limit=None,
        since_token=None,
        search_filter=None,
        include_all_networks=False,
        third_party_instance_id=None,
    ):
        if not self.enable_room_list_search:
            return {"chunk": [], "total_room_count_estimate": 0}

        if search_filter:
            # Searching across federation is defined in MSC2197.
            # However, the remote homeserver may or may not actually support it.
            # So we first try an MSC2197 remote-filtered search, then fall back
            # to a locally-filtered search if we must.

            try:
                res = yield self._get_remote_list_cached(
                    server_name,
                    limit=limit,
                    since_token=since_token,
                    include_all_networks=include_all_networks,
                    third_party_instance_id=third_party_instance_id,
                    search_filter=search_filter,
                )
                return res
            except HttpResponseException as hre:
                syn_err = hre.to_synapse_error()
                if hre.code in (404, 405) or syn_err.errcode in (
                    Codes.UNRECOGNIZED,
                    Codes.NOT_FOUND,
                ):
                    logger.debug("Falling back to locally-filtered /publicRooms")
                else:
                    raise  # Not an error that should trigger a fallback.

            # if we reach this point, then we fall back to the situation where
            # we currently don't support searching across federation, so we have
            # to do it manually without pagination
            limit = None
            since_token = None

        res = yield self._get_remote_list_cached(
            server_name,
            limit=limit,
            since_token=since_token,
            include_all_networks=include_all_networks,
            third_party_instance_id=third_party_instance_id,
        )

        if search_filter:
            res = {
                "chunk": [
                    entry
                    for entry in list(res.get("chunk", []))
                    if _matches_room_entry(entry, search_filter)
                ]
            }

        return res

    def _get_remote_list_cached(
        self,
        server_name,
        limit=None,
        since_token=None,
        search_filter=None,
        include_all_networks=False,
        third_party_instance_id=None,
    ):
        repl_layer = self.hs.get_federation_client()
        if search_filter:
            # We can't cache when asking for search
            return repl_layer.get_public_rooms(
                server_name,
                limit=limit,
                since_token=since_token,
                search_filter=search_filter,
                include_all_networks=include_all_networks,
                third_party_instance_id=third_party_instance_id,
            )

        key = (
            server_name,
            limit,
            since_token,
            include_all_networks,
            third_party_instance_id,
        )
        return self.remote_response_cache.wrap(
            key,
            repl_layer.get_public_rooms,
            server_name,
            limit=limit,
            since_token=since_token,
            search_filter=search_filter,
            include_all_networks=include_all_networks,
            third_party_instance_id=third_party_instance_id,
        )


class RoomListNextBatch(
    namedtuple(
        "RoomListNextBatch",
        (
            "stream_ordering",  # stream_ordering of the first public room list
            "public_room_stream_id",  # public room stream id for first public room list
            "current_limit",  # The number of previous rooms returned
            "direction_is_forward",  # Bool if this is a next_batch, false if prev_batch
        ),
    )
):
    KEY_DICT = {
        "stream_ordering": "s",
        "public_room_stream_id": "p",
        "current_limit": "n",
        "direction_is_forward": "d",
    }

    REVERSE_KEY_DICT = {v: k for k, v in KEY_DICT.items()}

    @classmethod
    def from_token(cls, token):
        if PY3:
            # The argument raw=False is only available on new versions of
            # msgpack, and only really needed on Python 3. Gate it behind
            # a PY3 check to avoid causing issues on Debian-packaged versions.
            decoded = msgpack.loads(decode_base64(token), raw=False)
        else:
            decoded = msgpack.loads(decode_base64(token))
        return RoomListNextBatch(
            **{cls.REVERSE_KEY_DICT[key]: val for key, val in decoded.items()}
        )

    def to_token(self):
        return encode_base64(
            msgpack.dumps(
                {self.KEY_DICT[key]: val for key, val in self._asdict().items()}
            )
        )

    def copy_and_replace(self, **kwds):
        return self._replace(**kwds)


def _matches_room_entry(room_entry, search_filter):
    if search_filter and search_filter.get("generic_search_term", None):
        generic_search_term = search_filter["generic_search_term"].upper()
        if generic_search_term in room_entry.get("name", "").upper():
            return True
        elif generic_search_term in room_entry.get("topic", "").upper():
            return True
        elif generic_search_term in room_entry.get("canonical_alias", "").upper():
            return True
    else:
        return True

    return False
