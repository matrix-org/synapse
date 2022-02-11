# Copyright 2019 New Vector Ltd
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

"""This class implements the proposed relation APIs from MSC 1849.

Since the MSC has not been approved all APIs here are unstable and may change at
any time to reflect changes in the MSC.
"""

import logging
from typing import TYPE_CHECKING, Optional, Tuple

from synapse.api.constants import RelationTypes
from synapse.api.errors import SynapseError
from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet, parse_integer, parse_string
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.storage.relations import (
    AggregationPaginationToken,
    PaginationChunk,
    RelationPaginationToken,
)
from synapse.types import JsonDict, RoomStreamToken, StreamToken

if TYPE_CHECKING:
    from synapse.server import HomeServer
    from synapse.storage.databases.main import DataStore

logger = logging.getLogger(__name__)


async def _parse_token(
    store: "DataStore", token: Optional[str]
) -> Optional[StreamToken]:
    """
    For backwards compatibility support RelationPaginationToken, but new pagination
    tokens are generated as full StreamTokens, to be compatible with /sync and /messages.
    """
    if not token:
        return None
    # Luckily the format for StreamToken and RelationPaginationToken differ enough
    # that they can easily be separated. An "_" appears in the serialization of
    # RoomStreamToken (as part of StreamToken), but RelationPaginationToken uses
    # "-" only for separators.
    if "_" in token:
        return await StreamToken.from_string(store, token)
    else:
        relation_token = RelationPaginationToken.from_string(token)
        return StreamToken(
            room_key=RoomStreamToken(relation_token.topological, relation_token.stream),
            presence_key=0,
            typing_key=0,
            receipt_key=0,
            account_data_key=0,
            push_rules_key=0,
            to_device_key=0,
            device_list_key=0,
            groups_key=0,
        )


class RelationPaginationServlet(RestServlet):
    """API to paginate relations on an event by topological ordering, optionally
    filtered by relation type and event type.
    """

    PATTERNS = client_patterns(
        "/rooms/(?P<room_id>[^/]*)/relations/(?P<parent_id>[^/]*)"
        "(/(?P<relation_type>[^/]*)(/(?P<event_type>[^/]*))?)?$",
        releases=(),
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.store = hs.get_datastore()
        self.clock = hs.get_clock()
        self._event_serializer = hs.get_event_client_serializer()
        self.event_handler = hs.get_event_handler()

    async def on_GET(
        self,
        request: SynapseRequest,
        room_id: str,
        parent_id: str,
        relation_type: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)

        await self.auth.check_user_in_room_or_world_readable(
            room_id, requester.user.to_string(), allow_departed_users=True
        )

        # This gets the original event and checks that a) the event exists and
        # b) the user is allowed to view it.
        event = await self.event_handler.get_event(requester.user, room_id, parent_id)
        if event is None:
            raise SynapseError(404, "Unknown parent event.")

        limit = parse_integer(request, "limit", default=5)
        direction = parse_string(
            request, "org.matrix.msc3715.dir", default="b", allowed_values=["f", "b"]
        )
        from_token_str = parse_string(request, "from")
        to_token_str = parse_string(request, "to")

        if event.internal_metadata.is_redacted():
            # If the event is redacted, return an empty list of relations
            pagination_chunk = PaginationChunk(chunk=[])
        else:
            # Return the relations
            from_token = await _parse_token(self.store, from_token_str)
            to_token = await _parse_token(self.store, to_token_str)

            pagination_chunk = await self.store.get_relations_for_event(
                event_id=parent_id,
                room_id=room_id,
                relation_type=relation_type,
                event_type=event_type,
                limit=limit,
                direction=direction,
                from_token=from_token,
                to_token=to_token,
            )

        events = await self.store.get_events_as_list(
            [c["event_id"] for c in pagination_chunk.chunk]
        )

        now = self.clock.time_msec()
        # Do not bundle aggregations when retrieving the original event because
        # we want the content before relations are applied to it.
        original_event = self._event_serializer.serialize_event(
            event, now, bundle_aggregations=None
        )
        # The relations returned for the requested event do include their
        # bundled aggregations.
        aggregations = await self.store.get_bundled_aggregations(
            events, requester.user.to_string()
        )
        serialized_events = self._event_serializer.serialize_events(
            events, now, bundle_aggregations=aggregations
        )

        return_value = await pagination_chunk.to_dict(self.store)
        return_value["chunk"] = serialized_events
        return_value["original_event"] = original_event

        return 200, return_value


class RelationAggregationPaginationServlet(RestServlet):
    """API to paginate aggregation groups of relations, e.g. paginate the
    types and counts of the reactions on the events.

    Example request and response:

        GET /rooms/{room_id}/aggregations/{parent_id}

        {
            chunk: [
                {
                    "type": "m.reaction",
                    "key": "👍",
                    "count": 3
                }
            ]
        }
    """

    PATTERNS = client_patterns(
        "/rooms/(?P<room_id>[^/]*)/aggregations/(?P<parent_id>[^/]*)"
        "(/(?P<relation_type>[^/]*)(/(?P<event_type>[^/]*))?)?$",
        releases=(),
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.store = hs.get_datastore()
        self.event_handler = hs.get_event_handler()

    async def on_GET(
        self,
        request: SynapseRequest,
        room_id: str,
        parent_id: str,
        relation_type: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)

        await self.auth.check_user_in_room_or_world_readable(
            room_id,
            requester.user.to_string(),
            allow_departed_users=True,
        )

        # This checks that a) the event exists and b) the user is allowed to
        # view it.
        event = await self.event_handler.get_event(requester.user, room_id, parent_id)
        if event is None:
            raise SynapseError(404, "Unknown parent event.")

        if relation_type not in (RelationTypes.ANNOTATION, None):
            raise SynapseError(
                400, f"Relation type must be '{RelationTypes.ANNOTATION}'"
            )

        limit = parse_integer(request, "limit", default=5)
        from_token_str = parse_string(request, "from")
        to_token_str = parse_string(request, "to")

        if event.internal_metadata.is_redacted():
            # If the event is redacted, return an empty list of relations
            pagination_chunk = PaginationChunk(chunk=[])
        else:
            # Return the relations
            from_token = None
            if from_token_str:
                from_token = AggregationPaginationToken.from_string(from_token_str)

            to_token = None
            if to_token_str:
                to_token = AggregationPaginationToken.from_string(to_token_str)

            pagination_chunk = await self.store.get_aggregation_groups_for_event(
                event_id=parent_id,
                room_id=room_id,
                event_type=event_type,
                limit=limit,
                from_token=from_token,
                to_token=to_token,
            )

        return 200, await pagination_chunk.to_dict(self.store)


class RelationAggregationGroupPaginationServlet(RestServlet):
    """API to paginate within an aggregation group of relations, e.g. paginate
    all the 👍 reactions on an event.

    Example request and response:

        GET /rooms/{room_id}/aggregations/{parent_id}/m.annotation/m.reaction/👍

        {
            chunk: [
                {
                    "type": "m.reaction",
                    "content": {
                        "m.relates_to": {
                            "rel_type": "m.annotation",
                            "key": "👍"
                        }
                    }
                },
                ...
            ]
        }
    """

    PATTERNS = client_patterns(
        "/rooms/(?P<room_id>[^/]*)/aggregations/(?P<parent_id>[^/]*)"
        "/(?P<relation_type>[^/]*)/(?P<event_type>[^/]*)/(?P<key>[^/]*)$",
        releases=(),
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.store = hs.get_datastore()
        self.clock = hs.get_clock()
        self._event_serializer = hs.get_event_client_serializer()
        self.event_handler = hs.get_event_handler()

    async def on_GET(
        self,
        request: SynapseRequest,
        room_id: str,
        parent_id: str,
        relation_type: str,
        event_type: str,
        key: str,
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)

        await self.auth.check_user_in_room_or_world_readable(
            room_id,
            requester.user.to_string(),
            allow_departed_users=True,
        )

        # This checks that a) the event exists and b) the user is allowed to
        # view it.
        event = await self.event_handler.get_event(requester.user, room_id, parent_id)
        if event is None:
            raise SynapseError(404, "Unknown parent event.")

        if relation_type != RelationTypes.ANNOTATION:
            raise SynapseError(400, "Relation type must be 'annotation'")

        limit = parse_integer(request, "limit", default=5)
        from_token_str = parse_string(request, "from")
        to_token_str = parse_string(request, "to")

        from_token = await _parse_token(self.store, from_token_str)
        to_token = await _parse_token(self.store, to_token_str)

        result = await self.store.get_relations_for_event(
            event_id=parent_id,
            room_id=room_id,
            relation_type=relation_type,
            event_type=event_type,
            aggregation_key=key,
            limit=limit,
            from_token=from_token,
            to_token=to_token,
        )

        events = await self.store.get_events_as_list(
            [c["event_id"] for c in result.chunk]
        )

        now = self.clock.time_msec()
        serialized_events = self._event_serializer.serialize_events(events, now)

        return_value = await result.to_dict(self.store)
        return_value["chunk"] = serialized_events

        return 200, return_value


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    RelationPaginationServlet(hs).register(http_server)
    RelationAggregationPaginationServlet(hs).register(http_server)
    RelationAggregationGroupPaginationServlet(hs).register(http_server)
