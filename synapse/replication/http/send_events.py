# Copyright 2022 The Matrix.org Foundation C.I.C.
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

from synapse.api.room_versions import KNOWN_ROOM_VERSIONS
from synapse.events import EventBase, make_event_from_dict
from synapse.events.snapshot import EventContext
from synapse.http.server import HttpServer
from synapse.http.servlet import parse_json_object_from_request
from synapse.replication.http._base import ReplicationEndpoint
from synapse.types import JsonDict, Requester, UserID
from synapse.util.metrics import Measure

if TYPE_CHECKING:
    from synapse.server import HomeServer
    from synapse.storage.databases.main import DataStore

logger = logging.getLogger(__name__)


class ReplicationSendEventsRestServlet(ReplicationEndpoint):
    """Handles batches of newly created events on workers, including persisting and
    notifying.

    The API looks like:

        POST /_synapse/replication/send_events/:txn_id

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
                "requester": { .. serialized requester .. },
                "ratelimit": true,
            }]
        }

        200 OK

        { "stream_id": 12345, "event_id": "$abcdef..." }

    Responds with a 409 when a `PartialStateConflictError` is raised due to an event
    context that needs to be recomputed due to the un-partial stating of a room.

    """

    NAME = "send_events"
    PATH_ARGS = ()

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self.event_creation_handler = hs.get_event_creation_handler()
        self.store = hs.get_datastores().main
        self._storage_controllers = hs.get_storage_controllers()
        self.clock = hs.get_clock()

    @staticmethod
    async def _serialize_payload(  # type: ignore[override]
        events_and_context: List[Tuple[EventBase, EventContext]],
        store: "DataStore",
        requester: Requester,
        ratelimit: bool,
        extra_users: List[UserID],
    ) -> JsonDict:
        """
        Args:
            store
            requester
            events_and_ctx
            ratelimit
        """
        serialized_events = []

        for event, context in events_and_context:
            serialized_context = await context.serialize(event, store)
            serialized_event = {
                "event": event.get_pdu_json(),
                "room_version": event.room_version.identifier,
                "event_format_version": event.format_version,
                "internal_metadata": event.internal_metadata.get_dict(),
                "outlier": event.internal_metadata.is_outlier(),
                "rejected_reason": event.rejected_reason,
                "context": serialized_context,
                "requester": requester.serialize(),
                "ratelimit": ratelimit,
                "extra_users": [u.to_string() for u in extra_users],
            }
            serialized_events.append(serialized_event)

        payload = {"events": serialized_events}

        return payload

    async def _handle_request(  # type: ignore[override]
        self, request: Request
    ) -> Tuple[int, JsonDict]:
        with Measure(self.clock, "repl_send_events_parse"):
            payload = parse_json_object_from_request(request)
            events_and_context = []
            events = payload["events"]

            for event_payload in events:
                event_dict = event_payload["event"]
                room_ver = KNOWN_ROOM_VERSIONS[event_payload["room_version"]]
                internal_metadata = event_payload["internal_metadata"]
                rejected_reason = event_payload["rejected_reason"]

                event = make_event_from_dict(
                    event_dict, room_ver, internal_metadata, rejected_reason
                )
                event.internal_metadata.outlier = event_payload["outlier"]

                requester = Requester.deserialize(
                    self.store, event_payload["requester"]
                )
                context = EventContext.deserialize(
                    self._storage_controllers, event_payload["context"]
                )

                ratelimit = event_payload["ratelimit"]
                events_and_context.append((event, context))

                extra_users = [
                    UserID.from_string(u) for u in event_payload["extra_users"]
                ]

                logger.info(
                    "Got batch of events to send, last ID of batch is: %s, sending into room: %s",
                    event.event_id,
                    event.room_id,
                )

            last_event = (
                await self.event_creation_handler.persist_and_notify_client_events(
                    requester, events_and_context, ratelimit, extra_users
                )
            )

        return (
            200,
            {
                "stream_id": last_event.internal_metadata.stream_ordering,
                "event_id": last_event.event_id,
            },
        )


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    ReplicationSendEventsRestServlet(hs).register(http_server)
