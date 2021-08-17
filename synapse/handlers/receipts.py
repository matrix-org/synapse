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
from typing import TYPE_CHECKING, List, Optional, Tuple

from synapse.api.constants import ReadReceiptEventFields
from synapse.appservice import ApplicationService
from synapse.handlers._base import BaseHandler
from synapse.types import JsonDict, ReadReceipt, UserID, get_domain_from_id

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class ReceiptsHandler(BaseHandler):
    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self.server_name = hs.config.server_name
        self.store = hs.get_datastore()
        self.event_auth_handler = hs.get_event_auth_handler()

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
                "m.receipt", self._received_remote_receipt
            )
        else:
            hs.get_federation_registry().register_instances_for_edu(
                "m.receipt",
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
            is_in_room = await self.event_auth_handler.check_host_in_room(
                room_id, self.server_name
            )
            if not is_in_room:
                logger.info(
                    "Ignoring receipt for room %r from server %s as we're not in the room",
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

                    receipts.append(
                        ReadReceipt(
                            room_id=room_id,
                            receipt_type=receipt_type,
                            user_id=user_id,
                            event_ids=user_values["event_ids"],
                            data=user_values.get("data", {}),
                        )
                    )

        await self._handle_new_receipts(receipts)

    async def _handle_new_receipts(self, receipts: List[ReadReceipt]) -> bool:
        """Takes a list of receipts, stores them and informs the notifier."""
        min_batch_id: Optional[int] = None
        max_batch_id: Optional[int] = None

        for receipt in receipts:
            res = await self.store.insert_receipt(
                receipt.room_id,
                receipt.receipt_type,
                receipt.user_id,
                receipt.event_ids,
                receipt.data,
            )

            if not res:
                # res will be None if this read receipt is 'old'
                continue

            stream_id, max_persisted_id = res

            if min_batch_id is None or stream_id < min_batch_id:
                min_batch_id = stream_id
            if max_batch_id is None or max_persisted_id > max_batch_id:
                max_batch_id = max_persisted_id

        # Either both of these should be None or neither.
        if min_batch_id is None or max_batch_id is None:
            # no new receipts
            return False

        affected_room_ids = list({r.room_id for r in receipts})

        self.notifier.on_new_event("receipt_key", max_batch_id, rooms=affected_room_ids)
        # Note that the min here shouldn't be relied upon to be accurate.
        await self.hs.get_pusherpool().on_new_receipts(
            min_batch_id, max_batch_id, affected_room_ids
        )

        return True

    async def received_client_receipt(
        self, room_id: str, receipt_type: str, user_id: str, event_id: str, hidden: bool
    ) -> None:
        """Called when a client tells us a local user has read up to the given
        event_id in the room.
        """
        receipt = ReadReceipt(
            room_id=room_id,
            receipt_type=receipt_type,
            user_id=user_id,
            event_ids=[event_id],
            data={"ts": int(self.clock.time_msec()), "hidden": hidden},
        )

        is_new = await self._handle_new_receipts([receipt])
        if not is_new:
            return

        if self.federation_sender and not (
            self.hs.config.experimental.msc2285_enabled and hidden
        ):
            await self.federation_sender.send_read_receipt(receipt)


class ReceiptEventSource:
    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastore()
        self.config = hs.config

    @staticmethod
    def filter_out_hidden(events: List[JsonDict], user_id: str) -> List[JsonDict]:
        visible_events = []

        # filter out hidden receipts the user shouldn't see
        for event in events:
            content = event.get("content", {})
            new_event = event.copy()
            new_event["content"] = {}

            for event_id in content.keys():
                event_content = content.get(event_id, {})
                m_read = event_content.get("m.read", {})

                # If m_read is missing copy over the original event_content as there is nothing to process here
                if not m_read:
                    new_event["content"][event_id] = event_content.copy()
                    continue

                new_users = {}
                for rr_user_id, user_rr in m_read.items():
                    try:
                        hidden = user_rr.get("hidden")
                    except AttributeError:
                        # Due to https://github.com/matrix-org/synapse/issues/10376
                        # there are cases where user_rr is a string, in those cases
                        # we just ignore the read receipt
                        continue

                    if hidden is not True or rr_user_id == user_id:
                        new_users[rr_user_id] = user_rr.copy()
                        # If hidden has a value replace hidden with the correct prefixed key
                        if hidden is not None:
                            new_users[rr_user_id].pop("hidden")
                            new_users[rr_user_id][
                                ReadReceiptEventFields.MSC2285_HIDDEN
                            ] = hidden

                # Set new users unless empty
                if len(new_users.keys()) > 0:
                    new_event["content"][event_id] = {"m.read": new_users}

            # Append new_event to visible_events unless empty
            if len(new_event["content"].keys()) > 0:
                visible_events.append(new_event)

        return visible_events

    async def get_new_events(
        self, from_key: int, room_ids: List[str], user: UserID, **kwargs
    ) -> Tuple[List[JsonDict], int]:
        from_key = int(from_key)
        to_key = self.get_current_key()

        if from_key == to_key:
            return [], to_key

        events = await self.store.get_linearized_receipts_for_rooms(
            room_ids, from_key=from_key, to_key=to_key
        )

        if self.config.experimental.msc2285_enabled:
            events = ReceiptEventSource.filter_out_hidden(events, user.to_string())

        return (events, to_key)

    async def get_new_events_as(
        self, from_key: int, service: ApplicationService
    ) -> Tuple[List[JsonDict], int]:
        """Returns a set of new receipt events that an appservice
        may be interested in.

        Args:
            from_key: the stream position at which events should be fetched from
            service: The appservice which may be interested
        """
        from_key = int(from_key)
        to_key = self.get_current_key()

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
            if not await service.matches_user_in_member_list(room_id, self.store):
                continue

            events.append(event)

        return (events, to_key)

    def get_current_key(self, direction: str = "f") -> int:
        return self.store.get_max_receipt_stream_id()
