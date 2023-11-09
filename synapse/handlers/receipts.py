# Copyright 2015, 2016 OpenMarket Ltd
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
from typing import TYPE_CHECKING, Iterable, List, Optional, Sequence, Tuple

from synapse.api.constants import EduTypes, ReceiptTypes
from synapse.appservice import ApplicationService
from synapse.streams import EventSource
from synapse.types import (
    JsonDict,
    JsonMapping,
    MultiWriterStreamToken,
    ReadReceipt,
    StreamKeyType,
    UserID,
    get_domain_from_id,
)

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class ReceiptsHandler:
    def __init__(self, hs: "HomeServer"):
        self.notifier = hs.get_notifier()
        self.server_name = hs.config.server.server_name
        self.store = hs.get_datastores().main
        self.event_auth_handler = hs.get_event_auth_handler()
        self.event_handler = hs.get_event_handler()
        self._storage_controllers = hs.get_storage_controllers()

        self.hs = hs

        # We only need to poke the federation sender explicitly if its on the
        # same instance. Other federation sender instances will get notified by
        # `synapse.app.generic_worker.FederationSenderHandler` when it sees it
        # in the receipts stream.
        self.federation_sender = None
        if hs.should_send_federation():
            self.federation_sender = hs.get_federation_sender()

        # If we can handle the receipt EDUs we do so, otherwise we route them
        # to the appropriate worker.
        if hs.get_instance_name() in hs.config.worker.writers.receipts:
            hs.get_federation_registry().register_edu_handler(
                EduTypes.RECEIPT, self._received_remote_receipt
            )
        else:
            hs.get_federation_registry().register_instances_for_edu(
                EduTypes.RECEIPT,
                hs.config.worker.writers.receipts,
            )

        self.clock = self.hs.get_clock()
        self.state = hs.get_state_handler()

    async def _received_remote_receipt(self, origin: str, content: JsonDict) -> None:
        """Called when we receive an EDU of type m.receipt from a remote HS."""
        receipts = []
        for room_id, room_values in content.items():
            # If we're not in the room just ditch the event entirely. This is
            # probably an old server that has come back and thinks we're still in
            # the room (or we've been rejoined to the room by a state reset).
            is_in_room = await self.event_auth_handler.is_host_in_room(
                room_id, self.server_name
            )
            if not is_in_room:
                logger.info(
                    "Ignoring receipt for room %r from server %s as we're not in the room",
                    room_id,
                    origin,
                )
                continue

            # Let's check that the origin server is in the room before accepting the receipt.
            # We don't want to block waiting on a partial state so take an
            # approximation if needed.
            domains = await self._storage_controllers.state.get_current_hosts_in_room_or_partial_state_approximation(
                room_id
            )
            if origin not in domains:
                logger.info(
                    "Ignoring receipt for room %r from server %s as they're not in the room",
                    room_id,
                    origin,
                )
                continue

            for receipt_type, users in room_values.items():
                for user_id, user_values in users.items():
                    if get_domain_from_id(user_id) != origin:
                        logger.info(
                            "Received receipt for user %r from server %s, ignoring",
                            user_id,
                            origin,
                        )
                        continue

                    # Check if these receipts apply to a thread.
                    data = user_values.get("data", {})
                    thread_id = data.get("thread_id")
                    # If the thread ID is invalid, consider it missing.
                    if not isinstance(thread_id, str):
                        thread_id = None

                    receipts.append(
                        ReadReceipt(
                            room_id=room_id,
                            receipt_type=receipt_type,
                            user_id=user_id,
                            event_ids=user_values["event_ids"],
                            thread_id=thread_id,
                            data=data,
                        )
                    )

        await self._handle_new_receipts(receipts)

    async def _handle_new_receipts(self, receipts: List[ReadReceipt]) -> bool:
        """Takes a list of receipts, stores them and informs the notifier."""

        receipts_persisted: List[ReadReceipt] = []
        for receipt in receipts:
            stream_id = await self.store.insert_receipt(
                receipt.room_id,
                receipt.receipt_type,
                receipt.user_id,
                receipt.event_ids,
                receipt.thread_id,
                receipt.data,
            )

            if stream_id is None:
                # stream_id will be None if this receipt is 'old'
                continue

            receipts_persisted.append(receipt)

        if not receipts_persisted:
            # no new receipts
            return False

        max_batch_id = self.store.get_max_receipt_stream_id()

        affected_room_ids = list({r.room_id for r in receipts_persisted})

        self.notifier.on_new_event(
            StreamKeyType.RECEIPT, max_batch_id, rooms=affected_room_ids
        )
        # Note that the min here shouldn't be relied upon to be accurate.
        await self.hs.get_pusherpool().on_new_receipts(
            {r.user_id for r in receipts_persisted}
        )

        return True

    async def received_client_receipt(
        self,
        room_id: str,
        receipt_type: str,
        user_id: UserID,
        event_id: str,
        thread_id: Optional[str],
    ) -> None:
        """Called when a client tells us a local user has read up to the given
        event_id in the room.
        """

        # Ensure the room/event exists, this will raise an error if the user
        # cannot view the event.
        if not await self.event_handler.get_event(user_id, room_id, event_id):
            return

        receipt = ReadReceipt(
            room_id=room_id,
            receipt_type=receipt_type,
            user_id=user_id.to_string(),
            event_ids=[event_id],
            thread_id=thread_id,
            data={"ts": int(self.clock.time_msec())},
        )

        is_new = await self._handle_new_receipts([receipt])
        if not is_new:
            return

        if self.federation_sender and receipt_type != ReceiptTypes.READ_PRIVATE:
            await self.federation_sender.send_read_receipt(receipt)


class ReceiptEventSource(EventSource[MultiWriterStreamToken, JsonMapping]):
    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastores().main
        self.config = hs.config

    @staticmethod
    def filter_out_private_receipts(
        rooms: Sequence[JsonMapping], user_id: str
    ) -> List[JsonMapping]:
        """
        Filters a list of serialized receipts (as returned by /sync and /initialSync)
        and removes private read receipts of other users.

        This operates on the return value of get_linearized_receipts_for_rooms(),
        which is wrapped in a cache. Care must be taken to ensure that the input
        values are not modified.

        Args:
            rooms: A list of mappings, each mapping has a `content` field, which
                is a map of event ID -> receipt type -> user ID -> receipt information.

        Returns:
            The same as rooms, but filtered.
        """

        result: List[JsonMapping] = []

        # Iterate through each room's receipt content.
        for room in rooms:
            # The receipt content with other user's private read receipts removed.
            content = {}

            # Iterate over each event ID / receipts for that event.
            for event_id, orig_event_content in room.get("content", {}).items():
                event_content = orig_event_content
                # If there are private read receipts, additional logic is necessary.
                if ReceiptTypes.READ_PRIVATE in event_content:
                    # Make a copy without private read receipts to avoid leaking
                    # other user's private read receipts..
                    event_content = {
                        receipt_type: receipt_value
                        for receipt_type, receipt_value in event_content.items()
                        if receipt_type != ReceiptTypes.READ_PRIVATE
                    }

                    # Copy the current user's private read receipt from the
                    # original content, if it exists.
                    user_private_read_receipt = orig_event_content[
                        ReceiptTypes.READ_PRIVATE
                    ].get(user_id, None)
                    if user_private_read_receipt:
                        event_content[ReceiptTypes.READ_PRIVATE] = {
                            user_id: user_private_read_receipt
                        }

                # Include the event if there is at least one non-private read
                # receipt or the current user has a private read receipt.
                if event_content:
                    content[event_id] = event_content

            # Include the event if there is at least one non-private read receipt
            # or the current user has a private read receipt.
            if content:
                # Build a new event to avoid mutating the cache.
                new_room = {k: v for k, v in room.items() if k != "content"}
                new_room["content"] = content
                result.append(new_room)

        return result

    async def get_new_events(
        self,
        user: UserID,
        from_key: MultiWriterStreamToken,
        limit: int,
        room_ids: Iterable[str],
        is_guest: bool,
        explicit_room_id: Optional[str] = None,
    ) -> Tuple[List[JsonMapping], MultiWriterStreamToken]:
        to_key = self.get_current_key()

        if from_key == to_key:
            return [], to_key

        events = await self.store.get_linearized_receipts_for_rooms(
            room_ids, from_key=from_key, to_key=to_key
        )

        events = ReceiptEventSource.filter_out_private_receipts(
            events, user.to_string()
        )

        return events, to_key

    async def get_new_events_as(
        self,
        from_key: MultiWriterStreamToken,
        to_key: MultiWriterStreamToken,
        service: ApplicationService,
    ) -> Tuple[List[JsonMapping], MultiWriterStreamToken]:
        """Returns a set of new read receipt events that an appservice
        may be interested in.

        Args:
            from_key: the stream position at which events should be fetched from
            to_key: the stream position up to which events should be fetched to
            service: The appservice which may be interested

        Returns:
            A two-tuple containing the following:
                * A list of json dictionaries derived from read receipts that the
                  appservice may be interested in.
                * The current read receipt stream token.
        """
        if from_key == to_key:
            return [], to_key

        # Fetch all read receipts for all rooms, up to a limit of 100. This is ordered
        # by most recent.
        rooms_to_events = await self.store.get_linearized_receipts_for_all_rooms(
            from_key=from_key, to_key=to_key
        )

        # Then filter down to rooms that the AS can read
        events = []
        for room_id, event in rooms_to_events.items():
            if not await service.is_interested_in_room(room_id, self.store):
                continue

            events.append(event)

        return events, to_key

    def get_current_key(self) -> MultiWriterStreamToken:
        return self.store.get_max_receipt_stream_id()
