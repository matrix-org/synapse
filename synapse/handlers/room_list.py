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
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

import attr
import msgpack
from unpaddedbase64 import decode_base64, encode_base64

from synapse.api.constants import (
    EventContentFields,
    EventTypes,
    GuestAccess,
    HistoryVisibility,
    JoinRules,
    PublicRoomsFilterFields,
)
from synapse.api.errors import (
    Codes,
    HttpResponseException,
    RequestSendFailed,
    SynapseError,
)
from synapse.types import JsonDict, JsonMapping, PublicRoom, ThirdPartyInstanceID
from synapse.util import filter_none
from synapse.util.caches.descriptors import _CacheContext, cached
from synapse.util.caches.response_cache import ResponseCache

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

REMOTE_ROOM_LIST_POLL_INTERVAL = 60 * 1000

# This is used to indicate we should only return rooms published to the main list.
EMPTY_THIRD_PARTY_ID = ThirdPartyInstanceID(None, None)


class RoomListHandler:
    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastores().main
        self._storage_controllers = hs.get_storage_controllers()
        self.hs = hs
        self.enable_room_list_search = hs.config.roomdirectory.enable_room_list_search
        self.response_cache: ResponseCache[
            Tuple[Optional[int], Optional[str], Optional[ThirdPartyInstanceID]]
        ] = ResponseCache(hs.get_clock(), "room_list")
        self.remote_response_cache: ResponseCache[
            Tuple[str, Optional[int], Optional[str], bool, Optional[str]]
        ] = ResponseCache(hs.get_clock(), "remote_room_list", timeout_ms=30 * 1000)
        self._module_api_callbacks = hs.get_module_api_callbacks().public_rooms

    async def get_local_public_room_list(
        self,
        limit: Optional[int] = None,
        since_token: Optional[str] = None,
        search_filter: Optional[dict] = None,
        network_tuple: Optional[ThirdPartyInstanceID] = EMPTY_THIRD_PARTY_ID,
        from_client_mxid: Optional[str] = None,
        from_remote_server_name: Optional[str] = None,
    ) -> JsonDict:
        """Generate a local public room list.

        There are multiple different lists: the main one plus one per third
        party network. A client can ask for a specific list or to return all.

        Args:
            limit: The maximum number of rooms to return, or None to return all rooms.
            since_token: A pagination token, or None to return the head of the public
                rooms list.
            search_filter: An optional dictionary with the following keys:
                * generic_search_term: A string to search for in room ...
                * room_types: A list to filter returned rooms by their type. If None or
                    an empty list is passed, rooms will not be filtered by type.
            network_tuple: Which public list to use.
                This can be (None, None) to indicate the main list, or a particular
                appservice and network id to use an appservice specific one.
                Setting to None returns all public rooms across all lists.
            from_client_mxid: A user's MXID if this request came from a registered user.
            from_remote_server_name: A remote homeserver's server name, if this
                request came from the federation API.
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
                from_client_mxid=from_client_mxid,
                from_remote_server_name=from_remote_server_name,
            )

        key = (limit, since_token, network_tuple)
        return await self.response_cache.wrap(
            key,
            self._get_public_room_list,
            limit,
            since_token,
            network_tuple=network_tuple,
            from_client_mxid=from_client_mxid,
            from_remote_server_name=from_remote_server_name,
        )

    async def _get_public_room_list(
        self,
        limit: Optional[int] = None,
        since_token: Optional[str] = None,
        search_filter: Optional[dict] = None,
        network_tuple: Optional[ThirdPartyInstanceID] = EMPTY_THIRD_PARTY_ID,
        from_client_mxid: Optional[str] = None,
        from_remote_server_name: Optional[str] = None,
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
            from_client_mxid: A user's MXID if this request came from a registered user.
            from_remote_server_name: A remote homeserver's server name, if this
                request came from the federation API.
        """

        # Pagination tokens work by storing the room ID sent in the last batch,
        # plus the direction (forwards or backwards). Next batch tokens always
        # go forwards, prev batch tokens always go backwards.

        forwards = True
        last_joined_members = None
        last_room_id = None
        last_module_index = None
        if since_token:
            batch_token = RoomListNextBatch.from_token(since_token)
            print(batch_token)
            forwards = batch_token.direction_is_forward
            last_joined_members = batch_token.last_joined_members
            last_room_id = batch_token.last_room_id
            last_module_index = batch_token.last_module_index

        # We request one more than wanted to see if there are more pages to come
        probing_limit = limit + 1 if limit is not None else None

        # We bucket results per joined members number since we want to keep order
        # per joined members number
        num_joined_members_buckets: Dict[int, List[PublicRoom]] = {}
        room_ids_to_module_index: Dict[str, int] = {}

        local_public_rooms = await self.store.get_largest_public_rooms(
            network_tuple,
            search_filter,
            probing_limit,
            bounds=(
                last_joined_members,
                last_room_id if last_module_index is None else None,
            ),
            forwards=forwards,
            ignore_non_federatable=bool(from_remote_server_name),
        )

        for room in local_public_rooms:
            num_joined_members_buckets.setdefault(room.num_joined_members, []).append(
                room
            )

        nb_modules = len(self._module_api_callbacks.fetch_public_rooms_callbacks)

        module_range = range(nb_modules)
        # if not forwards:
        #     module_range = reversed(module_range)

        for module_index in module_range:
            fetch_public_rooms = (
                self._module_api_callbacks.fetch_public_rooms_callbacks[module_index]
            )
            # Ask each module for a list of public rooms given the last_joined_members
            # value from the since token and the probing limit
            # last_joined_members needs to be reduce by one if this module has already
            # given its result for last_joined_members
            module_last_joined_members = last_joined_members
            if module_last_joined_members is not None and last_module_index is not None:
                if forwards and module_index < last_module_index:
                    module_last_joined_members = module_last_joined_members - 1
                # if not forwards and module_index > last_module_index:
                #     module_last_joined_members = module_last_joined_members - 1

            module_public_rooms = await fetch_public_rooms(
                network_tuple,
                search_filter,
                probing_limit,
                (
                    module_last_joined_members,
                    last_room_id if last_module_index == module_index else None,
                ),
                forwards,
            )

            for room in module_public_rooms:
                num_joined_members_buckets.setdefault(
                    room.num_joined_members, []
                ).append(room)
                room_ids_to_module_index[room.room_id] = module_index

        nums_joined_members = list(num_joined_members_buckets.keys())
        nums_joined_members.sort(reverse=forwards)

        results = []
        for num_joined_members in nums_joined_members:
            rooms = num_joined_members_buckets[num_joined_members]
            # if not forwards:
            #     rooms.reverse()
            results += rooms

        print([(r.room_id, r.num_joined_members) for r in results])

        response: JsonDict = {}
        num_results = len(results)
        if limit is not None and probing_limit is not None:
            more_to_come = num_results >= probing_limit

            # Depending on direction we trim either the front or back.
            if forwards:
                results = results[:limit]
            else:
                results = results[-limit:]
        else:
            more_to_come = False

        print([(r.room_id, r.num_joined_members) for r in results])

        if num_results > 0:
            final_entry = results[-1]
            initial_entry = results[0]

            if forwards:
                if since_token is not None:
                    # If there was a token given then we assume that there
                    # must be previous results.
                    response["prev_batch"] = RoomListNextBatch(
                        last_joined_members=initial_entry.num_joined_members,
                        last_room_id=initial_entry.room_id,
                        direction_is_forward=False,
                        last_module_index=room_ids_to_module_index.get(
                            initial_entry.room_id
                        ),
                    ).to_token()

                if more_to_come:
                    response["next_batch"] = RoomListNextBatch(
                        last_joined_members=final_entry.num_joined_members,
                        last_room_id=final_entry.room_id,
                        direction_is_forward=True,
                        last_module_index=room_ids_to_module_index.get(
                            final_entry.room_id
                        ),
                    ).to_token()
            else:
                if since_token is not None:
                    response["next_batch"] = RoomListNextBatch(
                        last_joined_members=final_entry.num_joined_members,
                        last_room_id=final_entry.room_id,
                        direction_is_forward=True,
                        last_module_index=room_ids_to_module_index.get(
                            final_entry.room_id
                        ),
                    ).to_token()

                if more_to_come:
                    response["prev_batch"] = RoomListNextBatch(
                        last_joined_members=initial_entry.num_joined_members,
                        last_room_id=initial_entry.room_id,
                        direction_is_forward=False,
                        last_module_index=room_ids_to_module_index.get(
                            initial_entry.room_id
                        ),
                    ).to_token()

        response["chunk"] = [attr.asdict(r, filter=filter_none) for r in results]

        response["total_room_count_estimate"] = await self.store.count_public_rooms(
            network_tuple,
            ignore_non_federatable=bool(from_remote_server_name),
            search_filter=search_filter,
        )

        return response

    @cached(num_args=1, cache_context=True)
    async def generate_room_entry(
        self,
        room_id: str,
        num_joined_users: int,
        cache_context: _CacheContext,
        with_alias: bool = True,
        allow_private: bool = False,
    ) -> Optional[JsonMapping]:
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

        current_state_ids = await self._storage_controllers.state.get_current_state_ids(
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
        result["m.federate"] = create_event.content.get(
            EventContentFields.FEDERATE, True
        )

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
            guest = guest_event.content.get(EventContentFields.GUEST_ACCESS)
        result["guest_can_join"] = guest == GuestAccess.CAN_JOIN

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
        """Get the public room list from remote server

        Raises:
            SynapseError
        """

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
                    # Not an error that should trigger a fallback.
                    raise SynapseError(502, "Failed to fetch room list")
            except RequestSendFailed:
                # Not an error that should trigger a fallback.
                raise SynapseError(502, "Failed to fetch room list")

            # if we reach this point, then we fall back to the situation where
            # we currently don't support searching across federation, so we have
            # to do it manually without pagination
            limit = None
            since_token = None

        try:
            res = await self._get_remote_list_cached(
                server_name,
                limit=limit,
                since_token=since_token,
                include_all_networks=include_all_networks,
                third_party_instance_id=third_party_instance_id,
            )
        except (RequestSendFailed, HttpResponseException):
            raise SynapseError(502, "Failed to fetch room list")

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
        """Wrapper around FederationClient.get_public_rooms that caches the
        result.
        """

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


@attr.s(slots=True, frozen=True, auto_attribs=True)
class RoomListNextBatch:
    last_joined_members: int  # The count to get rooms after/before
    last_room_id: str  # The room_id to get rooms after/before
    direction_is_forward: bool  # True if this is a next_batch, false if prev_batch
    last_module_index: Optional[int] = None

    KEY_DICT = {
        "last_joined_members": "m",
        "last_room_id": "r",
        "direction_is_forward": "d",
        "last_module_index": "i",
    }

    REVERSE_KEY_DICT = {v: k for k, v in KEY_DICT.items()}

    @classmethod
    def from_token(cls, token: str) -> "RoomListNextBatch":
        decoded = msgpack.loads(decode_base64(token), raw=False)
        return RoomListNextBatch(
            **{cls.REVERSE_KEY_DICT[key]: val for key, val in decoded.items()}
        )

    def to_token(self) -> str:
        # print(self)
        return encode_base64(
            msgpack.dumps(
                {self.KEY_DICT[key]: val for key, val in attr.asdict(self).items()}
            )
        )

    def copy_and_replace(self, **kwds: Any) -> "RoomListNextBatch":
        return attr.evolve(self, **kwds)


def _matches_room_entry(room_entry: JsonDict, search_filter: dict) -> bool:
    """Determines whether the given search filter matches a room entry returned over
    federation.

    Only used if the remote server does not support MSC2197 remote-filtered search, and
    hence does not support MSC3827 filtering of `/publicRooms` by room type either.

    In this case, we cannot apply the `room_type` filter since no `room_type` field is
    returned.
    """
    if search_filter and search_filter.get(
        PublicRoomsFilterFields.GENERIC_SEARCH_TERM, None
    ):
        generic_search_term = search_filter[
            PublicRoomsFilterFields.GENERIC_SEARCH_TERM
        ].upper()
        if generic_search_term in room_entry.get("name", "").upper():
            return True
        elif generic_search_term in room_entry.get("topic", "").upper():
            return True
        elif generic_search_term in room_entry.get("canonical_alias", "").upper():
            return True
    else:
        return True

    return False
