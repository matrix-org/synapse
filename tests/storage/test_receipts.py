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

from parameterized import parameterized

from synapse.api.constants import ReceiptTypes
from synapse.types import UserID, create_requester

from tests.test_utils.event_injection import create_event
from tests.unittest import HomeserverTestCase

OTHER_USER_ID = "@other:test"
OUR_USER_ID = "@our:test"


class ReceiptTestCase(HomeserverTestCase):
    def prepare(self, reactor, clock, homeserver) -> None:
        super().prepare(reactor, clock, homeserver)

        self.store = homeserver.get_datastores().main

        self.room_creator = homeserver.get_room_creation_handler()
        self.persist_event_storage_controller = (
            self.hs.get_storage_controllers().persistence
        )

        # Create a test user
        self.ourUser = UserID.from_string(OUR_USER_ID)
        self.ourRequester = create_requester(self.ourUser)

        # Create a second test user
        self.otherUser = UserID.from_string(OTHER_USER_ID)
        self.otherRequester = create_requester(self.otherUser)

        # Create a test room
        info, _ = self.get_success(self.room_creator.create_room(self.ourRequester, {}))
        self.room_id1 = info["room_id"]

        # Create a second test room
        info, _ = self.get_success(self.room_creator.create_room(self.ourRequester, {}))
        self.room_id2 = info["room_id"]

        # Join the second user to the first room
        memberEvent, memberEventContext = self.get_success(
            create_event(
                self.hs,
                room_id=self.room_id1,
                type="m.room.member",
                sender=self.otherRequester.user.to_string(),
                state_key=self.otherRequester.user.to_string(),
                content={"membership": "join"},
            )
        )
        self.get_success(
            self.persist_event_storage_controller.persist_event(
                memberEvent, memberEventContext
            )
        )

        # Join the second user to the second room
        memberEvent, memberEventContext = self.get_success(
            create_event(
                self.hs,
                room_id=self.room_id2,
                type="m.room.member",
                sender=self.otherRequester.user.to_string(),
                state_key=self.otherRequester.user.to_string(),
                content={"membership": "join"},
            )
        )
        self.get_success(
            self.persist_event_storage_controller.persist_event(
                memberEvent, memberEventContext
            )
        )

    def test_return_empty_with_no_data(self) -> None:
        res = self.get_success(
            self.store.get_receipts_for_user(
                OUR_USER_ID,
                [
                    ReceiptTypes.READ,
                    ReceiptTypes.READ_PRIVATE,
                    ReceiptTypes.UNSTABLE_READ_PRIVATE,
                ],
            )
        )
        self.assertEqual(res, {})

        res = self.get_success(
            self.store.get_receipts_for_user_with_orderings(
                OUR_USER_ID,
                [
                    ReceiptTypes.READ,
                    ReceiptTypes.READ_PRIVATE,
                    ReceiptTypes.UNSTABLE_READ_PRIVATE,
                ],
            )
        )
        self.assertEqual(res, {})

        res = self.get_success(
            self.store.get_last_receipt_event_id_for_user(
                OUR_USER_ID,
                self.room_id1,
                [
                    ReceiptTypes.READ,
                    ReceiptTypes.READ_PRIVATE,
                    ReceiptTypes.UNSTABLE_READ_PRIVATE,
                ],
            )
        )
        self.assertEqual(res, None)

    @parameterized.expand(
        [ReceiptTypes.READ_PRIVATE, ReceiptTypes.UNSTABLE_READ_PRIVATE]
    )
    def test_get_receipts_for_user(self, receipt_type: str) -> None:
        # Send some events into the first room
        event1_1_id = self.create_and_send_event(
            self.room_id1, UserID.from_string(OTHER_USER_ID)
        )
        event1_2_id = self.create_and_send_event(
            self.room_id1, UserID.from_string(OTHER_USER_ID)
        )

        # Send public read receipt for the first event
        self.get_success(
            self.store.insert_receipt(
                self.room_id1, ReceiptTypes.READ, OUR_USER_ID, [event1_1_id], {}
            )
        )
        # Send private read receipt for the second event
        self.get_success(
            self.store.insert_receipt(
                self.room_id1, receipt_type, OUR_USER_ID, [event1_2_id], {}
            )
        )

        # Test we get the latest event when we want both private and public receipts
        res = self.get_success(
            self.store.get_receipts_for_user(
                OUR_USER_ID, [ReceiptTypes.READ, receipt_type]
            )
        )
        self.assertEqual(res, {self.room_id1: event1_2_id})

        # Test we get the older event when we want only public receipt
        res = self.get_success(
            self.store.get_receipts_for_user(OUR_USER_ID, [ReceiptTypes.READ])
        )
        self.assertEqual(res, {self.room_id1: event1_1_id})

        # Test we get the latest event when we want only the public receipt
        res = self.get_success(
            self.store.get_receipts_for_user(OUR_USER_ID, [receipt_type])
        )
        self.assertEqual(res, {self.room_id1: event1_2_id})

        # Test receipt updating
        self.get_success(
            self.store.insert_receipt(
                self.room_id1, ReceiptTypes.READ, OUR_USER_ID, [event1_2_id], {}
            )
        )
        res = self.get_success(
            self.store.get_receipts_for_user(OUR_USER_ID, [ReceiptTypes.READ])
        )
        self.assertEqual(res, {self.room_id1: event1_2_id})

        # Send some events into the second room
        event2_1_id = self.create_and_send_event(
            self.room_id2, UserID.from_string(OTHER_USER_ID)
        )

        # Test new room is reflected in what the method returns
        self.get_success(
            self.store.insert_receipt(
                self.room_id2, receipt_type, OUR_USER_ID, [event2_1_id], {}
            )
        )
        res = self.get_success(
            self.store.get_receipts_for_user(
                OUR_USER_ID, [ReceiptTypes.READ, receipt_type]
            )
        )
        self.assertEqual(res, {self.room_id1: event1_2_id, self.room_id2: event2_1_id})

    @parameterized.expand(
        [ReceiptTypes.READ_PRIVATE, ReceiptTypes.UNSTABLE_READ_PRIVATE]
    )
    def test_get_last_receipt_event_id_for_user(self, receipt_type: str) -> None:
        # Send some events into the first room
        event1_1_id = self.create_and_send_event(
            self.room_id1, UserID.from_string(OTHER_USER_ID)
        )
        event1_2_id = self.create_and_send_event(
            self.room_id1, UserID.from_string(OTHER_USER_ID)
        )

        # Send public read receipt for the first event
        self.get_success(
            self.store.insert_receipt(
                self.room_id1, ReceiptTypes.READ, OUR_USER_ID, [event1_1_id], {}
            )
        )
        # Send private read receipt for the second event
        self.get_success(
            self.store.insert_receipt(
                self.room_id1, receipt_type, OUR_USER_ID, [event1_2_id], {}
            )
        )

        # Test we get the latest event when we want both private and public receipts
        res = self.get_success(
            self.store.get_last_receipt_event_id_for_user(
                OUR_USER_ID,
                self.room_id1,
                [ReceiptTypes.READ, receipt_type],
            )
        )
        self.assertEqual(res, event1_2_id)

        # Test we get the older event when we want only public receipt
        res = self.get_success(
            self.store.get_last_receipt_event_id_for_user(
                OUR_USER_ID, self.room_id1, [ReceiptTypes.READ]
            )
        )
        self.assertEqual(res, event1_1_id)

        # Test we get the latest event when we want only the private receipt
        res = self.get_success(
            self.store.get_last_receipt_event_id_for_user(
                OUR_USER_ID, self.room_id1, [receipt_type]
            )
        )
        self.assertEqual(res, event1_2_id)

        # Test receipt updating
        self.get_success(
            self.store.insert_receipt(
                self.room_id1, ReceiptTypes.READ, OUR_USER_ID, [event1_2_id], {}
            )
        )
        res = self.get_success(
            self.store.get_last_receipt_event_id_for_user(
                OUR_USER_ID, self.room_id1, [ReceiptTypes.READ]
            )
        )
        self.assertEqual(res, event1_2_id)

        # Send some events into the second room
        event2_1_id = self.create_and_send_event(
            self.room_id2, UserID.from_string(OTHER_USER_ID)
        )

        # Test new room is reflected in what the method returns
        self.get_success(
            self.store.insert_receipt(
                self.room_id2, receipt_type, OUR_USER_ID, [event2_1_id], {}
            )
        )
        res = self.get_success(
            self.store.get_last_receipt_event_id_for_user(
                OUR_USER_ID,
                self.room_id2,
                [ReceiptTypes.READ, receipt_type],
            )
        )
        self.assertEqual(res, event2_1_id)
