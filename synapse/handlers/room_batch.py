import logging
from typing import TYPE_CHECKING, List, Tuple

from synapse.api.constants import EventContentFields, EventTypes
from synapse.appservice import ApplicationService
from synapse.http.servlet import assert_params_in_dict
from synapse.types import JsonDict, Requester, UserID, create_requester
from synapse.util.stringutils import random_string

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


def generate_fake_event_id() -> str:
    return "$fake_" + random_string(43)


class RoomBatchHandler:
    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.store = hs.get_datastore()
        self.state_store = hs.get_storage().state
        self.event_creation_handler = hs.get_event_creation_handler()
        self.room_member_handler = hs.get_room_member_handler()
        self.auth = hs.get_auth()

    async def inherit_depth_from_prev_ids(self, prev_event_ids: List[str]) -> int:
        """Finds the depth which would sort it after the most-recent
        prev_event_id but before the successors of those events. If no
        successors are found, we assume it's an historical extremity part of the
        current batch and use the same depth of the prev_event_ids.

        Args:
            prev_event_ids: List of prev event IDs

        Returns:
            Inherited depth
        """
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

    def create_insertion_event_dict(
        self, sender: str, room_id: str, origin_server_ts: int
    ) -> JsonDict:
        """Creates an event dict for an "insertion" event with the proper fields
        and a random batch ID.

        Args:
            sender: The event author MXID
            room_id: The room ID that the event belongs to
            origin_server_ts: Timestamp when the event was sent

        Returns:
            The new event dictionary to insert.
        """

        next_batch_id = random_string(8)
        insertion_event = {
            "type": EventTypes.MSC2716_INSERTION,
            "sender": sender,
            "room_id": room_id,
            "content": {
                EventContentFields.MSC2716_NEXT_BATCH_ID: next_batch_id,
                EventContentFields.MSC2716_HISTORICAL: True,
            },
            "origin_server_ts": origin_server_ts,
        }

        return insertion_event

    async def create_requester_for_user_id_from_app_service(
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

    async def get_most_recent_auth_event_ids_from_event_id_list(
        self, event_ids: List[str]
    ) -> List[str]:
        """Find the most recent auth event ids (derived from state events) that
        allowed that message to be sent. We will use this as a base
        to auth our historical messages against.

        Args:
            event_ids: List of event ID's to look at

        Returns:
            List of event ID's
        """

        (
            most_recent_prev_event_id,
            _,
        ) = await self.store.get_max_depth_of(event_ids)
        # mapping from (type, state_key) -> state_event_id
        prev_state_map = await self.state_store.get_state_ids_for_event(
            most_recent_prev_event_id
        )
        # List of state event ID's
        prev_state_ids = list(prev_state_map.values())
        auth_event_ids = prev_state_ids

        return auth_event_ids

    async def persist_state_events_at_start(
        self,
        state_events_at_start: List[JsonDict],
        room_id: str,
        initial_auth_event_ids: List[str],
        app_service_requester: Requester,
    ) -> List[str]:
        """Takes all `state_events_at_start` event dictionaries and creates/persists
        them as floating state events which don't resolve into the current room state.
        They are floating because they reference a fake prev_event which doesn't connect
        to the normal DAG at all.

        Args:
            state_events_at_start:
            room_id: Room where you want the events persisted in.
            initial_auth_event_ids: These will be the auth_events for the first
                state event created. Each event created afterwards will be
                added to the list of auth events for the next state event
                created.
            app_service_requester: The requester of an application service.

        Returns:
            List of state event ID's we just persisted
        """
        assert app_service_requester.app_service

        state_event_ids_at_start = []
        auth_event_ids = initial_auth_event_ids.copy()

        # Make the state events float off on their own so we don't have a
        # bunch of `@mxid joined the room` noise between each batch
        prev_event_id_for_state_chain = generate_fake_event_id()

        for state_event in state_events_at_start:
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

            # TODO: This is pretty much the same as some other code to handle inserting state in this file
            if event_dict["type"] == EventTypes.Member:
                membership = event_dict["content"].get("membership", None)
                event_id, _ = await self.room_member_handler.update_membership(
                    await self.create_requester_for_user_id_from_app_service(
                        state_event["sender"], app_service_requester.app_service
                    ),
                    target=UserID.from_string(event_dict["state_key"]),
                    room_id=room_id,
                    action=membership,
                    content=event_dict["content"],
                    outlier=True,
                    historical=True,
                    prev_event_ids=[prev_event_id_for_state_chain],
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
                    await self.create_requester_for_user_id_from_app_service(
                        state_event["sender"], app_service_requester.app_service
                    ),
                    event_dict,
                    outlier=True,
                    historical=True,
                    prev_event_ids=[prev_event_id_for_state_chain],
                    # Make sure to use a copy of this list because we modify it
                    # later in the loop here. Otherwise it will be the same
                    # reference and also update in the event when we append later.
                    auth_event_ids=auth_event_ids.copy(),
                )
                event_id = event.event_id

            state_event_ids_at_start.append(event_id)
            auth_event_ids.append(event_id)
            # Connect all the state in a floating chain
            prev_event_id_for_state_chain = event_id

        return state_event_ids_at_start

    async def persist_historical_events(
        self,
        events_to_create: List[JsonDict],
        room_id: str,
        initial_prev_event_ids: List[str],
        inherited_depth: int,
        auth_event_ids: List[str],
        app_service_requester: Requester,
    ) -> List[str]:
        """Create and persists all events provided sequentially. Handles the
        complexity of creating events in chronological order so they can
        reference each other by prev_event but still persists in
        reverse-chronoloical order so they have the correct
        (topological_ordering, stream_ordering) and sort correctly from
        /messages.

        Args:
            events_to_create: List of historical events to create in JSON
                dictionary format.
            room_id: Room where you want the events persisted in.
            initial_prev_event_ids: These will be the prev_events for the first
                event created. Each event created afterwards will point to the
                previous event created.
            inherited_depth: The depth to create the events at (you will
                probably by calling inherit_depth_from_prev_ids(...)).
            auth_event_ids: Define which events allow you to create the given
                event in the room.
            app_service_requester: The requester of an application service.

        Returns:
            List of persisted event IDs
        """
        assert app_service_requester.app_service

        prev_event_ids = initial_prev_event_ids.copy()

        event_ids = []
        events_to_persist = []
        for ev in events_to_create:
            assert_params_in_dict(ev, ["type", "origin_server_ts", "content", "sender"])

            assert self.hs.is_mine_id(ev["sender"]), "User must be our own: %s" % (
                ev["sender"],
            )

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
                await self.create_requester_for_user_id_from_app_service(
                    ev["sender"], app_service_requester.app_service
                ),
                event_dict,
                prev_event_ids=event_dict.get("prev_events"),
                auth_event_ids=auth_event_ids,
                historical=True,
                depth=inherited_depth,
            )

            assert context._state_group

            # Normally this is done when persisting the event but we have to
            # pre-emptively do it here because we create all the events first,
            # then persist them in another pass below. And we want to share
            # state_groups across the whole batch so this lookup needs to work
            # for the next event in the batch in this loop.
            await self.store.store_state_group_id_for_event_id(
                event_id=event.event_id,
                state_group_id=context._state_group,
            )

            logger.debug(
                "RoomBatchSendEventRestServlet inserting event=%s, prev_event_ids=%s, auth_event_ids=%s",
                event,
                prev_event_ids,
                auth_event_ids,
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
            await self.event_creation_handler.handle_new_client_event(
                await self.create_requester_for_user_id_from_app_service(
                    event.sender, app_service_requester.app_service
                ),
                event=event,
                context=context,
            )

        return event_ids

    async def handle_batch_of_events(
        self,
        events_to_create: List[JsonDict],
        room_id: str,
        batch_id_to_connect_to: str,
        initial_prev_event_ids: List[str],
        inherited_depth: int,
        auth_event_ids: List[str],
        app_service_requester: Requester,
    ) -> Tuple[List[str], str]:
        """
        Handles creating and persisting all of the historical events as well
        as insertion and batch meta events to make the batch navigable in the DAG.

        Args:
            events_to_create: List of historical events to create in JSON
                dictionary format.
            room_id: Room where you want the events created in.
            batch_id_to_connect_to: The batch_id from the insertion event you
                want this batch to connect to.
            initial_prev_event_ids: These will be the prev_events for the first
                event created. Each event created afterwards will point to the
                previous event created.
            inherited_depth: The depth to create the events at (you will
                probably by calling inherit_depth_from_prev_ids(...)).
            auth_event_ids: Define which events allow you to create the given
                event in the room.
            app_service_requester: The requester of an application service.

        Returns:
            Tuple containing a list of created events and the next_batch_id
        """

        # Connect this current batch to the insertion event from the previous batch
        last_event_in_batch = events_to_create[-1]
        batch_event = {
            "type": EventTypes.MSC2716_BATCH,
            "sender": app_service_requester.user.to_string(),
            "room_id": room_id,
            "content": {
                EventContentFields.MSC2716_BATCH_ID: batch_id_to_connect_to,
                EventContentFields.MSC2716_HISTORICAL: True,
            },
            # Since the batch event is put at the end of the batch,
            # where the newest-in-time event is, copy the origin_server_ts from
            # the last event we're inserting
            "origin_server_ts": last_event_in_batch["origin_server_ts"],
        }
        # Add the batch event to the end of the batch (newest-in-time)
        events_to_create.append(batch_event)

        # Add an "insertion" event to the start of each batch (next to the oldest-in-time
        # event in the batch) so the next batch can be connected to this one.
        insertion_event = self.create_insertion_event_dict(
            sender=app_service_requester.user.to_string(),
            room_id=room_id,
            # Since the insertion event is put at the start of the batch,
            # where the oldest-in-time event is, copy the origin_server_ts from
            # the first event we're inserting
            origin_server_ts=events_to_create[0]["origin_server_ts"],
        )
        next_batch_id = insertion_event["content"][
            EventContentFields.MSC2716_NEXT_BATCH_ID
        ]
        # Prepend the insertion event to the start of the batch (oldest-in-time)
        events_to_create = [insertion_event] + events_to_create

        # Create and persist all of the historical events
        event_ids = await self.persist_historical_events(
            events_to_create=events_to_create,
            room_id=room_id,
            initial_prev_event_ids=initial_prev_event_ids,
            inherited_depth=inherited_depth,
            auth_event_ids=auth_event_ids,
            app_service_requester=app_service_requester,
        )

        return event_ids, next_batch_id
