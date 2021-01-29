# -*- coding: utf-8 -*-
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

from synapse.appservice import ApplicationService
from synapse.handlers._base import BaseHandler
from synapse.types import JsonDict, ReadReceipt, get_domain_from_id

if TYPE_CHECKING:
    from synapse.app.homeserver import HomeServer

logger = logging.getLogger(__name__)


class ReceiptsHandler(BaseHandler):
    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self.server_name = hs.config.server_name
        self.store = hs.get_datastore()
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
                "m.receipt", hs.config.worker.writers.receipts,
            )

        self.clock = self.hs.get_clock()
        self.state = hs.get_state_handler()

    async def _received_remote_receipt(self, origin: str, content: JsonDict) -> None:
        """Called when we receive an EDU of type m.receipt from a remote HS.
        """
        receipts = []
        for room_id, room_values in content.items():
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
        """Takes a list of receipts, stores them and informs the notifier.
        """
        min_batch_id = None  # type: Optional[int]
        max_batch_id = None  # type: Optional[int]

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
        self, room_id: str, receipt_type: str, user_id: str, event_id: str
    ) -> None:
        """Called when a client tells us a local user has read up to the given
        event_id in the room.
        """
        receipt = ReadReceipt(
            room_id=room_id,
            receipt_type=receipt_type,
            user_id=user_id,
            event_ids=[event_id],
            data={"ts": int(self.clock.time_msec())},
        )

        is_new = await self._handle_new_receipts([receipt])
        if not is_new:
            return

        if self.federation_sender:
            await self.federation_sender.send_read_receipt(receipt)


class ReceiptEventSource:
    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastore()

    async def get_new_events(
        self, from_key: int, room_ids: List[str], **kwargs
    ) -> Tuple[List[JsonDict], int]:
        from_key = int(from_key)
        to_key = self.get_current_key()

        if from_key == to_key:
            return [], to_key

        events = await self.store.get_linearized_receipts_for_rooms(
            room_ids, from_key=from_key, to_key=to_key
        )

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
