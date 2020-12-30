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
from typing import TYPE_CHECKING, Optional, Tuple

import msgpack
from unpaddedbase64 import decode_base64, encode_base64

from synapse.api.constants import EventTypes, HistoryVisibility, JoinRules
from synapse.api.errors import Codes, HttpResponseException
from synapse.types import JsonDict, ThirdPartyInstanceID
from synapse.util.caches.descriptors import cached
from synapse.util.caches.response_cache import ResponseCache

from ._base import BaseHandler

if TYPE_CHECKING:
    from synapse.app.homeserver import HomeServer

logger = logging.getLogger(__name__)

REMOTE_ROOM_LIST_POLL_INTERVAL = 60 * 1000

# This is used to indicate we should only return rooms published to the main list.
EMPTY_THIRD_PARTY_ID = ThirdPartyInstanceID(None, None)


class RoomListHandler(BaseHandler):
    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        self.enable_room_list_search = hs.config.enable_room_list_search
        self.response_cache = ResponseCache(
            hs, "room_list"
        )  # type: ResponseCache[Tuple[Optional[int], Optional[str], ThirdPartyInstanceID]]
        self.remote_response_cache = ResponseCache(
            hs, "remote_room_list", timeout_ms=30 * 1000
        )  # type: ResponseCache[Tuple[str, Optional[int], Optional[str], bool, Optional[str]]]

    async def get_local_public_room_list(
        self,
        limit: Optional[int] = None,
        since_token: Optional[str] = None,
        search_filter: Optional[dict] = None,
        network_tuple: ThirdPartyInstanceID = EMPTY_THIRD_PARTY_ID,
        from_federation: bool = False,
    ) -> JsonDict:
        """Generate a local public room list.

        There are multiple different lists: the main one plus one per third
        party network. A client can ask for a specific list or to return all.

        Args:
            limit
            since_token
            search_filter
            network_tuple: Which public list to use.
                This can be (None, None) to indicate the main list, or a particular
                appservice and network id to use an appservice specific one.
                Setting to None returns all public rooms across all lists.
            from_federation: true iff the request comes from the federation API
        """
        if not self.enable_room_list_search:
            return {"chunk": [], "total_room_count_estimate": 0}

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

            return await self._get_public_room_list(
                limit,
                since_token,
                search_filter,
                network_tuple=network_tuple,
                from_federation=from_federation,
            )

        key = (limit, since_token, network_tuple)
        return await self.response_cache.wrap(
            key,
            self._get_public_room_list,
            limit,
            since_token,
            network_tuple=network_tuple,
            from_federation=from_federation,
        )

    async def _get_public_room_list(
        self,
        limit: Optional[int] = None,
        since_token: Optional[str] = None,
        search_filter: Optional[dict] = None,
        network_tuple: ThirdPartyInstanceID = EMPTY_THIRD_PARTY_ID,
        from_federation: bool = False,
    ) -> JsonDict:
        """Generate a public room list.
        Args:
            limit: Maximum amount of rooms to return.
            since_token:
            search_filter: Dictionary to filter rooms by.
            network_tuple: Which public list to use.
                This can be (None, None) to indicate the main list, or a particular
                appservice and network id to use an appservice specific one.
                Setting to None returns all public rooms across all lists.
            from_federation: Whether this request originated from a
                federating server or a client. Used for room filtering.
        """

        # Pagination tokens work by storing the room ID sent in the last batch,
        # plus the direction (forwards or backwards). Next batch tokens always
        # go forwards, prev batch tokens always go backwards.

        if since_token:
            batch_token = RoomListNextBatch.from_token(since_token)

            bounds = (
                batch_token.last_joined_members,
                batch_token.last_room_id,
            )  # type: Optional[Tuple[int, str]]
            forwards = batch_token.direction_is_forward
            has_batch_token = True
        else:
            bounds = None

            forwards = True
            has_batch_token = False

        # we request one more than wanted to see if there are more pages to come
        probing_limit = limit + 1 if limit is not None else None

        results = await self.store.get_largest_public_rooms(
            network_tuple,
            search_filter,
            probing_limit,
            bounds=bounds,
            forwards=forwards,
            ignore_non_federatable=from_federation,
        )

        def build_room_entry(room):
            entry = {
                "room_id": room["room_id"],
                "name": room["name"],
                "topic": room["topic"],
                "canonical_alias": room["canonical_alias"],
                "num_joined_members": room["joined_members"],
                "avatar_url": room["avatar"],
                "world_readable": room["history_visibility"]
                == HistoryVisibility.WORLD_READABLE,
                "guest_can_join": room["guest_access"] == "can_join",
            }

            # Filter out Nones – rather omit the field altogether
            return {k: v for k, v in entry.items() if v is not None}

        results = [build_room_entry(r) for r in results]

        response = {}  # type: JsonDict
        num_results = len(results)
        if limit is not None:
            more_to_come = num_results == probing_limit

            # Depending on direction we trim either the front or back.
            if forwards:
                results = results[:limit]
            else:
                results = results[-limit:]
        else:
            more_to_come = False

        if num_results > 0:
            final_entry = results[-1]
            initial_entry = results[0]

            if forwards:
                if has_batch_token:
                    # If there was a token given then we assume that there
                    # must be previous results.
                    response["prev_batch"] = RoomListNextBatch(
                        last_joined_members=initial_entry["num_joined_members"],
                        last_room_id=initial_entry["room_id"],
                        direction_is_forward=False,
                    ).to_token()

                if more_to_come:
                    response["next_batch"] = RoomListNextBatch(
                        last_joined_members=final_entry["num_joined_members"],
                        last_room_id=final_entry["room_id"],
                        direction_is_forward=True,
                    ).to_token()
            else:
                if has_batch_token:
                    response["next_batch"] = RoomListNextBatch(
                        last_joined_members=final_entry["num_joined_members"],
                        last_room_id=final_entry["room_id"],
                        direction_is_forward=True,
                    ).to_token()

                if more_to_come:
                    response["prev_batch"] = RoomListNextBatch(
                        last_joined_members=initial_entry["num_joined_members"],
                        last_room_id=initial_entry["room_id"],
                        direction_is_forward=False,
                    ).to_token()

        response["chunk"] = results

        response["total_room_count_estimate"] = await self.store.count_public_rooms(
            network_tuple, ignore_non_federatable=from_federation
        )

        return response

    @cached(num_args=1, cache_context=True)
    async def generate_room_entry(
        self,
        room_id: str,
        num_joined_users: int,
        cache_context,
        with_alias: bool = True,
        allow_private: bool = False,
    ) -> Optional[dict]:
        """Returns the entry for a room

        Args:
            room_id: The room's ID.
            num_joined_users: Number of users in the room.
            cache_context: Information for cached responses.
            with_alias: Whether to return the room's aliases in the result.
            allow_private: Whether invite-only rooms should be shown.

        Returns:
            Returns a room entry as a dictionary, or None if this
            room was determined not to be shown publicly.
        """
        result = {"room_id": room_id, "num_joined_members": num_joined_users}

        if with_alias:
            aliases = await self.store.get_aliases_for_room(
                room_id, on_invalidate=cache_context.invalidate
            )
            if aliases:
                result["aliases"] = aliases

        current_state_ids = await self.store.get_current_state_ids(
            room_id, on_invalidate=cache_context.invalidate
        )

        if not current_state_ids:
            # We're not in the room, so may as well bail out here.
            return result

        event_map = await self.store.get_events(
            [
                event_id
                for key, event_id in current_state_ids.items()
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
        create_event = current_state[EventTypes.Create, ""]
        result["m.federate"] = create_event.content.get("m.federate", True)

        name_event = current_state.get((EventTypes.Name, ""))
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
        result["world_readable"] = visibility == HistoryVisibility.WORLD_READABLE

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

    async def get_remote_public_room_list(
        self,
        server_name: str,
        limit: Optional[int] = None,
        since_token: Optional[str] = None,
        search_filter: Optional[dict] = None,
        include_all_networks: bool = False,
        third_party_instance_id: Optional[str] = None,
    ) -> JsonDict:
        if not self.enable_room_list_search:
            return {"chunk": [], "total_room_count_estimate": 0}

        if search_filter:
            # Searching across federation is defined in MSC2197.
            # However, the remote homeserver may or may not actually support it.
            # So we first try an MSC2197 remote-filtered search, then fall back
            # to a locally-filtered search if we must.

            try:
                res = await self._get_remote_list_cached(
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

        res = await self._get_remote_list_cached(
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

    async def _get_remote_list_cached(
        self,
        server_name: str,
        limit: Optional[int] = None,
        since_token: Optional[str] = None,
        search_filter: Optional[dict] = None,
        include_all_networks: bool = False,
        third_party_instance_id: Optional[str] = None,
    ) -> JsonDict:
        repl_layer = self.hs.get_federation_client()
        if search_filter:
            # We can't cache when asking for search
            return await repl_layer.get_public_rooms(
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
        return await self.remote_response_cache.wrap(
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
            "last_joined_members",  # The count to get rooms after/before
            "last_room_id",  # The room_id to get rooms after/before
            "direction_is_forward",  # Bool if this is a next_batch, false if prev_batch
        ),
    )
):
    KEY_DICT = {
        "last_joined_members": "m",
        "last_room_id": "r",
        "direction_is_forward": "d",
    }

    REVERSE_KEY_DICT = {v: k for k, v in KEY_DICT.items()}

    @classmethod
    def from_token(cls, token: str) -> "RoomListNextBatch":
        decoded = msgpack.loads(decode_base64(token), raw=False)
        return RoomListNextBatch(
            **{cls.REVERSE_KEY_DICT[key]: val for key, val in decoded.items()}
        )

    def to_token(self) -> str:
        return encode_base64(
            msgpack.dumps(
                {self.KEY_DICT[key]: val for key, val in self._asdict().items()}
            )
        )

    def copy_and_replace(self, **kwds) -> "RoomListNextBatch":
        return self._replace(**kwds)


def _matches_room_entry(room_entry: JsonDict, search_filter: dict) -> bool:
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
