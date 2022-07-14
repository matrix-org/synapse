# Copyright 2018 New Vector Ltd
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
from typing import TYPE_CHECKING, List, Tuple

from twisted.web.server import Request

from synapse.api.room_versions import KNOWN_ROOM_VERSIONS, RoomVersion
from synapse.events import EventBase, make_event_from_dict
from synapse.events.snapshot import EventContext
from synapse.http.server import HttpServer
from synapse.http.servlet import parse_json_object_from_request
from synapse.replication.http._base import ReplicationEndpoint
from synapse.types import JsonDict
from synapse.util.metrics import Measure

if TYPE_CHECKING:
    from synapse.server import HomeServer
    from synapse.storage.databases.main import DataStore

logger = logging.getLogger(__name__)


class ReplicationFederationSendEventsRestServlet(ReplicationEndpoint):
    """Handles events newly received from federation, including persisting and
    notifying. Returns the maximum stream ID of the persisted events.

    The API looks like:

        POST /_synapse/replication/fed_send_events/:txn_id

        {
            "events": [{
                "event": { .. serialized event .. },
                "room_version": .., // "1", "2", "3", etc: the version of the room
                                    // containing the event
                "event_format_version": .., // 1,2,3 etc: the event format version
                "internal_metadata": { .. serialized internal_metadata .. },
                "outlier": true|false,
                "rejected_reason": ..,   // The event.rejected_reason field
                "context": { .. serialized event context .. },
            }],
            "backfilled": false
        }

        200 OK

        {
            "max_stream_id": 32443,
        }

    Responds with a 409 when a `PartialStateConflictError` is raised due to an event
    context that needs to be recomputed due to the un-partial stating of a room.
    """

    NAME = "fed_send_events"
    PATH_ARGS = ()

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self.store = hs.get_datastores().main
        self._storage_controllers = hs.get_storage_controllers()
        self.clock = hs.get_clock()
        self.federation_event_handler = hs.get_federation_event_handler()

    @staticmethod
    async def _serialize_payload(  # type: ignore[override]
        store: "DataStore",
        room_id: str,
        event_and_contexts: List[Tuple[EventBase, EventContext]],
        backfilled: bool,
    ) -> JsonDict:
        """
        Args:
            store
            room_id
            event_and_contexts
            backfilled: Whether or not the events are the result of backfilling
        """
        event_payloads = []
        for event, context in event_and_contexts:
            serialized_context = await context.serialize(event, store)

            event_payloads.append(
                {
                    "event": event.get_pdu_json(),
                    "room_version": event.room_version.identifier,
                    "event_format_version": event.format_version,
                    "internal_metadata": event.internal_metadata.get_dict(),
                    "outlier": event.internal_metadata.is_outlier(),
                    "rejected_reason": event.rejected_reason,
                    "context": serialized_context,
                }
            )

        payload = {
            "events": event_payloads,
            "backfilled": backfilled,
            "room_id": room_id,
        }

        return payload

    async def _handle_request(self, request: Request) -> Tuple[int, JsonDict]:  # type: ignore[override]
        with Measure(self.clock, "repl_fed_send_events_parse"):
            content = parse_json_object_from_request(request)

            room_id = content["room_id"]
            backfilled = content["backfilled"]

            event_payloads = content["events"]

            event_and_contexts = []
            for event_payload in event_payloads:
                event_dict = event_payload["event"]
                room_ver = KNOWN_ROOM_VERSIONS[event_payload["room_version"]]
                internal_metadata = event_payload["internal_metadata"]
                rejected_reason = event_payload["rejected_reason"]

                event = make_event_from_dict(
                    event_dict, room_ver, internal_metadata, rejected_reason
                )
                event.internal_metadata.outlier = event_payload["outlier"]

                context = EventContext.deserialize(
                    self._storage_controllers, event_payload["context"]
                )

                event_and_contexts.append((event, context))

        logger.info("Got %d events from federation", len(event_and_contexts))

        max_stream_id = await self.federation_event_handler.persist_events_and_notify(
            room_id, event_and_contexts, backfilled
        )

        return 200, {"max_stream_id": max_stream_id}


class ReplicationFederationSendEduRestServlet(ReplicationEndpoint):
    """Handles EDUs newly received from federation, including persisting and
    notifying.

    Request format:

        POST /_synapse/replication/fed_send_edu/:edu_type/:txn_id

        {
            "origin": ...,
            "content: { ... }
        }
    """

    NAME = "fed_send_edu"
    PATH_ARGS = ("edu_type",)

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self.store = hs.get_datastores().main
        self.clock = hs.get_clock()
        self.registry = hs.get_federation_registry()

    @staticmethod
    async def _serialize_payload(  # type: ignore[override]
        edu_type: str, origin: str, content: JsonDict
    ) -> JsonDict:
        return {"origin": origin, "content": content}

    async def _handle_request(  # type: ignore[override]
        self, request: Request, edu_type: str
    ) -> Tuple[int, JsonDict]:
        with Measure(self.clock, "repl_fed_send_edu_parse"):
            content = parse_json_object_from_request(request)

            origin = content["origin"]
            edu_content = content["content"]

        logger.info("Got %r edu from %s", edu_type, origin)

        await self.registry.on_edu(edu_type, origin, edu_content)

        return 200, {}


class ReplicationGetQueryRestServlet(ReplicationEndpoint):
    """Handle responding to queries from federation.

    Request format:

        POST /_synapse/replication/fed_query/:query_type

        {
            "args": { ... }
        }
    """

    NAME = "fed_query"
    PATH_ARGS = ("query_type",)

    # This is a query, so let's not bother caching
    CACHE = False

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self.store = hs.get_datastores().main
        self.clock = hs.get_clock()
        self.registry = hs.get_federation_registry()

    @staticmethod
    async def _serialize_payload(query_type: str, args: JsonDict) -> JsonDict:  # type: ignore[override]
        """
        Args:
            query_type
            args: The arguments received for the given query type
        """
        return {"args": args}

    async def _handle_request(  # type: ignore[override]
        self, request: Request, query_type: str
    ) -> Tuple[int, JsonDict]:
        with Measure(self.clock, "repl_fed_query_parse"):
            content = parse_json_object_from_request(request)

            args = content["args"]
            args["origin"] = content["origin"]

        logger.info("Got %r query from %s", query_type, args["origin"])

        result = await self.registry.on_query(query_type, args)

        return 200, result


class ReplicationCleanRoomRestServlet(ReplicationEndpoint):
    """Called to clean up any data in DB for a given room, ready for the
    server to join the room.

    Request format:

        POST /_synapse/replication/fed_cleanup_room/:room_id/:txn_id

        {}
    """

    NAME = "fed_cleanup_room"
    PATH_ARGS = ("room_id",)

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self.store = hs.get_datastores().main

    @staticmethod
    async def _serialize_payload(room_id: str) -> JsonDict:  # type: ignore[override]
        """
        Args:
            room_id
        """
        return {}

    async def _handle_request(  # type: ignore[override]
        self, request: Request, room_id: str
    ) -> Tuple[int, JsonDict]:
        await self.store.clean_room_for_join(room_id)

        return 200, {}


class ReplicationStoreRoomOnOutlierMembershipRestServlet(ReplicationEndpoint):
    """Called to clean up any data in DB for a given room, ready for the
    server to join the room.

    Request format:

        POST /_synapse/replication/store_room_on_outlier_membership/:room_id/:txn_id

        {
            "room_version": "1",
        }
    """

    NAME = "store_room_on_outlier_membership"
    PATH_ARGS = ("room_id",)

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self.store = hs.get_datastores().main

    @staticmethod
    async def _serialize_payload(room_id: str, room_version: RoomVersion) -> JsonDict:  # type: ignore[override]
        return {"room_version": room_version.identifier}

    async def _handle_request(  # type: ignore[override]
        self, request: Request, room_id: str
    ) -> Tuple[int, JsonDict]:
        content = parse_json_object_from_request(request)
        room_version = KNOWN_ROOM_VERSIONS[content["room_version"]]
        await self.store.maybe_store_room_on_outlier_membership(room_id, room_version)
        return 200, {}


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    ReplicationFederationSendEventsRestServlet(hs).register(http_server)
    ReplicationFederationSendEduRestServlet(hs).register(http_server)
    ReplicationGetQueryRestServlet(hs).register(http_server)
    ReplicationCleanRoomRestServlet(hs).register(http_server)
    ReplicationStoreRoomOnOutlierMembershipRestServlet(hs).register(http_server)
