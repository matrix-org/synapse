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

from synapse.api.constants import EventContentFields, EventTypes
from synapse.api.errors import AuthError, Codes, SynapseError
from synapse.appservice import ApplicationService
from synapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_json_object_from_request,
    parse_string,
    parse_strings_from_args,
)
from synapse.rest.client.transactions import HttpTransactionCache
from synapse.types import Requester, UserID, create_requester
from synapse.util.stringutils import random_string

logger = logging.getLogger(__name__)


class RoomBatchSendEventRestServlet(RestServlet):
    """
    API endpoint which can insert a chunk of events historically back in time
    next to the given `prev_event`.

    `chunk_id` comes from `next_chunk_id `in the response of the batch send
    endpoint and is derived from the "insertion" events added to each chunk.
    It's not required for the first batch send.

    `state_events_at_start` is used to define the historical state events
    needed to auth the events like join events. These events will float
    outside of the normal DAG as outlier's and won't be visible in the chat
    history which also allows us to insert multiple chunks without having a bunch
    of `@mxid joined the room` noise between each chunk.

    `events` is chronological chunk/list of events you want to insert.
    There is a reverse-chronological constraint on chunks so once you insert
    some messages, you can only insert older ones after that.
    tldr; Insert chunks from your most recent history -> oldest history.

    POST /_matrix/client/unstable/org.matrix.msc2716/rooms/<roomID>/batch_send?prev_event=<eventID>&chunk_id=<chunkID>
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

    def __init__(self, hs):
        super().__init__()
        self.hs = hs
        self.store = hs.get_datastore()
        self.state_store = hs.get_storage().state
        self.event_creation_handler = hs.get_event_creation_handler()
        self.room_member_handler = hs.get_room_member_handler()
        self.auth = hs.get_auth()
        self.txns = HttpTransactionCache(hs)

    async def _inherit_depth_from_prev_ids(self, prev_event_ids) -> int:
        (
            most_recent_prev_event_id,
            most_recent_prev_event_depth,
        ) = await self.store.get_max_depth_of(prev_event_ids)

        # We want to insert the historical event after the `prev_event` but before the successor event
        #
        # We inherit depth from the successor event instead of the `prev_event`
        # because events returned from `/messages` are first sorted by `topological_ordering`
        # which is just the `depth` and then tie-break with `stream_ordering`.
        #
        # We mark these inserted historical events as "backfilled" which gives them a
        # negative `stream_ordering`. If we use the same depth as the `prev_event`,
        # then our historical event will tie-break and be sorted before the `prev_event`
        # when it should come after.
        #
        # We want to use the successor event depth so they appear after `prev_event` because
        # it has a larger `depth` but before the successor event because the `stream_ordering`
        # is negative before the successor event.
        successor_event_ids = await self.store.get_successor_events(
            [most_recent_prev_event_id]
        )

        # If we can't find any successor events, then it's a forward extremity of
        # historical messages and we can just inherit from the previous historical
        # event which we can already assume has the correct depth where we want
        # to insert into.
        if not successor_event_ids:
            depth = most_recent_prev_event_depth
        else:
            (
                _,
                oldest_successor_depth,
            ) = await self.store.get_min_depth_of(successor_event_ids)

            depth = oldest_successor_depth

        return depth

    def _create_insertion_event_dict(
        self, sender: str, room_id: str, origin_server_ts: int
    ):
        """Creates an event dict for an "insertion" event with the proper fields
        and a random chunk ID.

        Args:
            sender: The event author MXID
            room_id: The room ID that the event belongs to
            origin_server_ts: Timestamp when the event was sent

        Returns:
            Tuple of event ID and stream ordering position
        """

        next_chunk_id = random_string(8)
        insertion_event = {
            "type": EventTypes.MSC2716_INSERTION,
            "sender": sender,
            "room_id": room_id,
            "content": {
                EventContentFields.MSC2716_NEXT_CHUNK_ID: next_chunk_id,
                EventContentFields.MSC2716_HISTORICAL: True,
            },
            "origin_server_ts": origin_server_ts,
        }

        return insertion_event

    async def _create_requester_for_user_id_from_app_service(
        self, user_id: str, app_service: ApplicationService
    ) -> Requester:
        """Creates a new requester for the given user_id
        and validates that the app service is allowed to control
        the given user.

        Args:
            user_id: The author MXID that the app service is controlling
            app_service: The app service that controls the user

        Returns:
            Requester object
        """

        await self.auth.validate_appservice_can_control_user_id(app_service, user_id)

        return create_requester(user_id, app_service=app_service)

    async def on_POST(self, request, room_id):
        requester = await self.auth.get_user_by_req(request, allow_guest=False)

        if not requester.app_service:
            raise AuthError(
                403,
                "Only application services can use the /batchsend endpoint",
            )

        body = parse_json_object_from_request(request)
        assert_params_in_dict(body, ["state_events_at_start", "events"])

        prev_events_from_query = parse_strings_from_args(request.args, "prev_event")
        chunk_id_from_query = parse_string(request, "chunk_id")

        if prev_events_from_query is None:
            raise SynapseError(
                400,
                "prev_event query parameter is required when inserting historical messages back in time",
                errcode=Codes.MISSING_PARAM,
            )

        # For the event we are inserting next to (`prev_events_from_query`),
        # find the most recent auth events (derived from state events) that
        # allowed that message to be sent. We will use that as a base
        # to auth our historical messages against.
        (
            most_recent_prev_event_id,
            _,
        ) = await self.store.get_max_depth_of(prev_events_from_query)
        # mapping from (type, state_key) -> state_event_id
        prev_state_map = await self.state_store.get_state_ids_for_event(
            most_recent_prev_event_id
        )
        # List of state event ID's
        prev_state_ids = list(prev_state_map.values())
        auth_event_ids = prev_state_ids

        state_events_at_start = []
        for state_event in body["state_events_at_start"]:
            assert_params_in_dict(
                state_event, ["type", "origin_server_ts", "content", "sender"]
            )

            logger.debug(
                "RoomBatchSendEventRestServlet inserting state_event=%s, auth_event_ids=%s",
                state_event,
                auth_event_ids,
            )

            event_dict = {
                "type": state_event["type"],
                "origin_server_ts": state_event["origin_server_ts"],
                "content": state_event["content"],
                "room_id": room_id,
                "sender": state_event["sender"],
                "state_key": state_event["state_key"],
            }

            # Mark all events as historical
            event_dict["content"][EventContentFields.MSC2716_HISTORICAL] = True

            # Make the state events float off on their own
            fake_prev_event_id = "$" + random_string(43)

            # TODO: This is pretty much the same as some other code to handle inserting state in this file
            if event_dict["type"] == EventTypes.Member:
                membership = event_dict["content"].get("membership", None)
                event_id, _ = await self.room_member_handler.update_membership(
                    await self._create_requester_for_user_id_from_app_service(
                        state_event["sender"], requester.app_service
                    ),
                    target=UserID.from_string(event_dict["state_key"]),
                    room_id=room_id,
                    action=membership,
                    content=event_dict["content"],
                    outlier=True,
                    prev_event_ids=[fake_prev_event_id],
                    # Make sure to use a copy of this list because we modify it
                    # later in the loop here. Otherwise it will be the same
                    # reference and also update in the event when we append later.
                    auth_event_ids=auth_event_ids.copy(),
                )
            else:
                # TODO: Add some complement tests that adds state that is not member joins
                # and will use this code path. Maybe we only want to support join state events
                # and can get rid of this `else`?
                (
                    event,
                    _,
                ) = await self.event_creation_handler.create_and_send_nonmember_event(
                    await self._create_requester_for_user_id_from_app_service(
                        state_event["sender"], requester.app_service
                    ),
                    event_dict,
                    outlier=True,
                    prev_event_ids=[fake_prev_event_id],
                    # Make sure to use a copy of this list because we modify it
                    # later in the loop here. Otherwise it will be the same
                    # reference and also update in the event when we append later.
                    auth_event_ids=auth_event_ids.copy(),
                )
                event_id = event.event_id

            state_events_at_start.append(event_id)
            auth_event_ids.append(event_id)

        events_to_create = body["events"]

        inherited_depth = await self._inherit_depth_from_prev_ids(
            prev_events_from_query
        )

        # Figure out which chunk to connect to. If they passed in
        # chunk_id_from_query let's use it. The chunk ID passed in comes
        # from the chunk_id in the "insertion" event from the previous chunk.
        last_event_in_chunk = events_to_create[-1]
        chunk_id_to_connect_to = chunk_id_from_query
        base_insertion_event = None
        if chunk_id_from_query:
            #  All but the first base insertion event should point at a fake
            #  event, which causes the HS to ask for the state at the start of
            #  the chunk later.
            prev_event_ids = [fake_prev_event_id]
            # TODO: Verify the chunk_id_from_query corresponds to an insertion event
            pass
        # Otherwise, create an insertion event to act as a starting point.
        #
        # We don't always have an insertion event to start hanging more history
        # off of (ideally there would be one in the main DAG, but that's not the
        # case if we're wanting to add history to e.g. existing rooms without
        # an insertion event), in which case we just create a new insertion event
        # that can then get pointed to by a "marker" event later.
        else:
            prev_event_ids = prev_events_from_query

            base_insertion_event_dict = self._create_insertion_event_dict(
                sender=requester.user.to_string(),
                room_id=room_id,
                origin_server_ts=last_event_in_chunk["origin_server_ts"],
            )
            base_insertion_event_dict["prev_events"] = prev_event_ids.copy()

            (
                base_insertion_event,
                _,
            ) = await self.event_creation_handler.create_and_send_nonmember_event(
                await self._create_requester_for_user_id_from_app_service(
                    base_insertion_event_dict["sender"],
                    requester.app_service,
                ),
                base_insertion_event_dict,
                prev_event_ids=base_insertion_event_dict.get("prev_events"),
                auth_event_ids=auth_event_ids,
                historical=True,
                depth=inherited_depth,
            )

            chunk_id_to_connect_to = base_insertion_event["content"][
                EventContentFields.MSC2716_NEXT_CHUNK_ID
            ]

        # Connect this current chunk to the insertion event from the previous chunk
        chunk_event = {
            "type": EventTypes.MSC2716_CHUNK,
            "sender": requester.user.to_string(),
            "room_id": room_id,
            "content": {
                EventContentFields.MSC2716_CHUNK_ID: chunk_id_to_connect_to,
                EventContentFields.MSC2716_HISTORICAL: True,
            },
            # Since the chunk event is put at the end of the chunk,
            # where the newest-in-time event is, copy the origin_server_ts from
            # the last event we're inserting
            "origin_server_ts": last_event_in_chunk["origin_server_ts"],
        }
        # Add the chunk event to the end of the chunk (newest-in-time)
        events_to_create.append(chunk_event)

        # Add an "insertion" event to the start of each chunk (next to the oldest-in-time
        # event in the chunk) so the next chunk can be connected to this one.
        insertion_event = self._create_insertion_event_dict(
            sender=requester.user.to_string(),
            room_id=room_id,
            # Since the insertion event is put at the start of the chunk,
            # where the oldest-in-time event is, copy the origin_server_ts from
            # the first event we're inserting
            origin_server_ts=events_to_create[0]["origin_server_ts"],
        )
        # Prepend the insertion event to the start of the chunk (oldest-in-time)
        events_to_create = [insertion_event] + events_to_create

        event_ids = []
        events_to_persist = []
        for ev in events_to_create:
            assert_params_in_dict(ev, ["type", "origin_server_ts", "content", "sender"])

            event_dict = {
                "type": ev["type"],
                "origin_server_ts": ev["origin_server_ts"],
                "content": ev["content"],
                "room_id": room_id,
                "sender": ev["sender"],  # requester.user.to_string(),
                "prev_events": prev_event_ids.copy(),
            }

            # Mark all events as historical
            event_dict["content"][EventContentFields.MSC2716_HISTORICAL] = True

            event, context = await self.event_creation_handler.create_event(
                await self._create_requester_for_user_id_from_app_service(
                    ev["sender"], requester.app_service
                ),
                event_dict,
                prev_event_ids=event_dict.get("prev_events"),
                auth_event_ids=auth_event_ids,
                historical=True,
                depth=inherited_depth,
            )
            logger.debug(
                "RoomBatchSendEventRestServlet inserting event=%s, prev_event_ids=%s, auth_event_ids=%s",
                event,
                prev_event_ids,
                auth_event_ids,
            )

            assert self.hs.is_mine_id(event.sender), "User must be our own: %s" % (
                event.sender,
            )

            events_to_persist.append((event, context))
            event_id = event.event_id

            event_ids.append(event_id)
            prev_event_ids = [event_id]

        # Persist events in reverse-chronological order so they have the
        # correct stream_ordering as they are backfilled (which decrements).
        # Events are sorted by (topological_ordering, stream_ordering)
        # where topological_ordering is just depth.
        for (event, context) in reversed(events_to_persist):
            ev = await self.event_creation_handler.handle_new_client_event(
                await self._create_requester_for_user_id_from_app_service(
                    event["sender"], requester.app_service
                ),
                event=event,
                context=context,
            )

        # Add the base_insertion_event to the bottom of the list we return
        if base_insertion_event is not None:
            event_ids.append(base_insertion_event.event_id)

        return 200, {
            "state_events": state_events_at_start,
            "events": event_ids,
            "next_chunk_id": insertion_event["content"][
                EventContentFields.MSC2716_NEXT_CHUNK_ID
            ],
        }

    def on_GET(self, request, room_id):
        return 501, "Not implemented"

    def on_PUT(self, request, room_id):
        return self.txns.fetch_or_execute_request(
            request, self.on_POST, request, room_id
        )


def register_servlets(hs, http_server):
    msc2716_enabled = hs.config.experimental.msc2716_enabled

    if msc2716_enabled:
        RoomBatchSendEventRestServlet(hs).register(http_server)
