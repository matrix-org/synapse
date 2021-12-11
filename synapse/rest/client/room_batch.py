# Copyright 2016 OpenMarket Ltd
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
import re
from http import HTTPStatus
from typing import TYPE_CHECKING, Awaitable, Tuple

from twisted.web.server import Request

from synapse.api.constants import EventContentFields
from synapse.api.errors import AuthError, Codes, SynapseError
from synapse.http.server import HttpServer
from synapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_json_object_from_request,
    parse_string,
    parse_strings_from_args,
)
from synapse.http.site import SynapseRequest
from synapse.rest.client.transactions import HttpTransactionCache
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class RoomBatchSendEventRestServlet(RestServlet):
    """
    API endpoint which can insert a batch of events historically back in time
    next to the given `prev_event`.

    `batch_id` comes from `next_batch_id `in the response of the batch send
    endpoint and is derived from the "insertion" events added to each batch.
    It's not required for the first batch send.

    `state_events_at_start` is used to define the historical state events
    needed to auth the events like join events. These events will float
    outside of the normal DAG as outlier's and won't be visible in the chat
    history which also allows us to insert multiple batches without having a bunch
    of `@mxid joined the room` noise between each batch.

    `events` is chronological list of events you want to insert.
    There is a reverse-chronological constraint on batches so once you insert
    some messages, you can only insert older ones after that.
    tldr; Insert batches from your most recent history -> oldest history.

    POST /_matrix/client/unstable/org.matrix.msc2716/rooms/<roomID>/batch_send?prev_event_id=<eventID>&batch_id=<batchID>
    {
        "events": [ ... ],
        "state_events_at_start": [ ... ]
    }
    """

    PATTERNS = (
        re.compile(
            "^/_matrix/client/unstable/org.matrix.msc2716"
            "/rooms/(?P<room_id>[^/]*)/batch_send$"
        ),
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.store = hs.get_datastore()
        self.event_creation_handler = hs.get_event_creation_handler()
        self.auth = hs.get_auth()
        self.room_batch_handler = hs.get_room_batch_handler()
        self.txns = HttpTransactionCache(hs)

    async def on_POST(
        self, request: SynapseRequest, room_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=False)

        if not requester.app_service:
            raise AuthError(
                HTTPStatus.FORBIDDEN,
                "Only application services can use the /batchsend endpoint",
            )

        body = parse_json_object_from_request(request)
        assert_params_in_dict(body, ["state_events_at_start", "events"])

        assert request.args is not None
        prev_event_ids_from_query = parse_strings_from_args(
            request.args, "prev_event_id"
        )
        batch_id_from_query = parse_string(request, "batch_id")

        if prev_event_ids_from_query is None:
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "prev_event query parameter is required when inserting historical messages back in time",
                errcode=Codes.MISSING_PARAM,
            )

        # Verify the batch_id_from_query corresponds to an actual insertion event
        # and have the batch connected.
        if batch_id_from_query:
            corresponding_insertion_event_id = (
                await self.store.get_insertion_event_id_by_batch_id(
                    room_id, batch_id_from_query
                )
            )
            if corresponding_insertion_event_id is None:
                raise SynapseError(
                    HTTPStatus.BAD_REQUEST,
                    "No insertion event corresponds to the given ?batch_id",
                    errcode=Codes.INVALID_PARAM,
                )

        # For the event we are inserting next to (`prev_event_ids_from_query`),
        # find the most recent auth events (derived from state events) that
        # allowed that message to be sent. We will use that as a base
        # to auth our historical messages against.
        auth_event_ids = await self.room_batch_handler.get_most_recent_auth_event_ids_from_event_id_list(
            prev_event_ids_from_query
        )

        state_event_ids_at_start = []
        # Create and persist all of the state events that float off on their own
        # before the batch. These will most likely be all of the invite/member
        # state events used to auth the upcoming historical messages.
        if body["state_events_at_start"]:
            state_event_ids_at_start = (
                await self.room_batch_handler.persist_state_events_at_start(
                    state_events_at_start=body["state_events_at_start"],
                    room_id=room_id,
                    initial_auth_event_ids=auth_event_ids,
                    app_service_requester=requester,
                )
            )
            # Update our ongoing auth event ID list with all of the new state we
            # just created
            auth_event_ids.extend(state_event_ids_at_start)

        inherited_depth = await self.room_batch_handler.inherit_depth_from_prev_ids(
            prev_event_ids_from_query
        )

        events_to_create = body["events"]

        # Figure out which batch to connect to. If they passed in
        # batch_id_from_query let's use it. The batch ID passed in comes
        # from the batch_id in the "insertion" event from the previous batch.
        last_event_in_batch = events_to_create[-1]
        base_insertion_event = None
        if batch_id_from_query:
            batch_id_to_connect_to = batch_id_from_query
        # Otherwise, create an insertion event to act as a starting point.
        #
        # We don't always have an insertion event to start hanging more history
        # off of (ideally there would be one in the main DAG, but that's not the
        # case if we're wanting to add history to e.g. existing rooms without
        # an insertion event), in which case we just create a new insertion event
        # that can then get pointed to by a "marker" event later.
        else:
            base_insertion_event_dict = (
                self.room_batch_handler.create_insertion_event_dict(
                    sender=requester.user.to_string(),
                    room_id=room_id,
                    origin_server_ts=last_event_in_batch["origin_server_ts"],
                )
            )
            base_insertion_event_dict["prev_events"] = prev_event_ids_from_query.copy()

            (
                base_insertion_event,
                _,
            ) = await self.event_creation_handler.create_and_send_nonmember_event(
                await self.room_batch_handler.create_requester_for_user_id_from_app_service(
                    base_insertion_event_dict["sender"],
                    requester.app_service,
                ),
                base_insertion_event_dict,
                prev_event_ids=base_insertion_event_dict.get("prev_events"),
                auth_event_ids=auth_event_ids,
                historical=True,
                depth=inherited_depth,
            )

            batch_id_to_connect_to = base_insertion_event.content[
                EventContentFields.MSC2716_NEXT_BATCH_ID
            ]

        # Also connect the historical event chain to the end of the floating
        # state chain, which causes the HS to ask for the state at the start of
        # the batch later. If there is no state chain to connect to, just make
        # the insertion event float itself.
        prev_event_ids = []
        if len(state_event_ids_at_start):
            prev_event_ids = [state_event_ids_at_start[-1]]

        # Create and persist all of the historical events as well as insertion
        # and batch meta events to make the batch navigable in the DAG.
        event_ids, next_batch_id = await self.room_batch_handler.handle_batch_of_events(
            events_to_create=events_to_create,
            room_id=room_id,
            batch_id_to_connect_to=batch_id_to_connect_to,
            initial_prev_event_ids=prev_event_ids,
            inherited_depth=inherited_depth,
            auth_event_ids=auth_event_ids,
            app_service_requester=requester,
        )

        insertion_event_id = event_ids[0]
        batch_event_id = event_ids[-1]
        historical_event_ids = event_ids[1:-1]

        response_dict = {
            "state_event_ids": state_event_ids_at_start,
            "event_ids": historical_event_ids,
            "next_batch_id": next_batch_id,
            "insertion_event_id": insertion_event_id,
            "batch_event_id": batch_event_id,
        }
        if base_insertion_event is not None:
            response_dict["base_insertion_event_id"] = base_insertion_event.event_id

        return HTTPStatus.OK, response_dict

    def on_GET(self, request: Request, room_id: str) -> Tuple[int, str]:
        return HTTPStatus.NOT_IMPLEMENTED, "Not implemented"

    def on_PUT(
        self, request: SynapseRequest, room_id: str
    ) -> Awaitable[Tuple[int, JsonDict]]:
        return self.txns.fetch_or_execute_request(
            request, self.on_POST, request, room_id
        )


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    msc2716_enabled = hs.config.experimental.msc2716_enabled

    if msc2716_enabled:
        RoomBatchSendEventRestServlet(hs).register(http_server)
