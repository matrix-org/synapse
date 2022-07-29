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

from synapse.api.constants import ReceiptTypes
from synapse.storage.databases.main.receipts import _BackgroundUpdates
from synapse.types import UserID, create_requester

from tests.test_utils.event_injection import create_event
from tests.unittest import HomeserverTestCase

OTHER_USER_ID = "@other:test"
OUR_USER_ID = "@our:test"


class ReceiptTestCase(HomeserverTestCase):
    def prepare(self, reactor, clock, homeserver):
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

    def test_return_empty_with_no_data(self):
        res = self.get_success(
            self.store.get_receipts_for_user(
                OUR_USER_ID, [ReceiptTypes.READ, ReceiptTypes.READ_PRIVATE]
            )
        )
        self.assertEqual(res, {})

        res = self.get_success(
            self.store.get_receipts_for_user_with_orderings(
                OUR_USER_ID,
                [ReceiptTypes.READ, ReceiptTypes.READ_PRIVATE],
            )
        )
        self.assertEqual(res, {})

        res = self.get_success(
            self.store.get_last_receipt_event_id_for_user(
                OUR_USER_ID,
                self.room_id1,
                [ReceiptTypes.READ, ReceiptTypes.READ_PRIVATE],
            )
        )
        self.assertEqual(res, None)

    def test_get_receipts_for_user(self):
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
                self.room_id1, ReceiptTypes.READ_PRIVATE, OUR_USER_ID, [event1_2_id], {}
            )
        )

        # Test we get the latest event when we want both private and public receipts
        res = self.get_success(
            self.store.get_receipts_for_user(
                OUR_USER_ID, [ReceiptTypes.READ, ReceiptTypes.READ_PRIVATE]
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
            self.store.get_receipts_for_user(OUR_USER_ID, [ReceiptTypes.READ_PRIVATE])
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
                self.room_id2, ReceiptTypes.READ_PRIVATE, OUR_USER_ID, [event2_1_id], {}
            )
        )
        res = self.get_success(
            self.store.get_receipts_for_user(
                OUR_USER_ID, [ReceiptTypes.READ, ReceiptTypes.READ_PRIVATE]
            )
        )
        self.assertEqual(res, {self.room_id1: event1_2_id, self.room_id2: event2_1_id})

    def test_get_last_receipt_event_id_for_user(self):
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
                self.room_id1, ReceiptTypes.READ_PRIVATE, OUR_USER_ID, [event1_2_id], {}
            )
        )

        # Test we get the latest event when we want both private and public receipts
        res = self.get_success(
            self.store.get_last_receipt_event_id_for_user(
                OUR_USER_ID,
                self.room_id1,
                [ReceiptTypes.READ, ReceiptTypes.READ_PRIVATE],
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
                OUR_USER_ID, self.room_id1, [ReceiptTypes.READ_PRIVATE]
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
                self.room_id2, ReceiptTypes.READ_PRIVATE, OUR_USER_ID, [event2_1_id], {}
            )
        )
        res = self.get_success(
            self.store.get_last_receipt_event_id_for_user(
                OUR_USER_ID,
                self.room_id2,
                [ReceiptTypes.READ, ReceiptTypes.READ_PRIVATE],
            )
        )
        self.assertEqual(res, event2_1_id)


class ReceiptsBackgroundUpdateStoreTestCase(HomeserverTestCase):
    def prepare(self, reactor, clock, hs):
        self.store = hs.get_datastores().main

    def test_background_remove_unstable_private_read_receipts(self):
        """
        Test that the background update removes unstable private read receipts
        (org.matrix.msc2285.read.private) from the `receipts_linearized` and
        `receipts_graph` tables.
        """

        READ_PRIVATE_UNSTABLE = "org.matrix.msc2285.read.private"

        # Fake a receipt of unstable private read receipt type in
        # `receipt_linearized`
        self.get_success(
            self.store.db_pool.simple_insert(
                table="receipts_linearized",
                values={
                    "room_id": "room_id",
                    "receipt_type": READ_PRIVATE_UNSTABLE,
                    "user_id": OUR_USER_ID,
                    "stream_id": "stream_id",
                    "event_id": "event_id",
                    "data": "{}",
                },
            )
        )
        # Fake a receipt of unstable private read receipt type in
        # `receipt_graph`
        self.get_success(
            self.store.db_pool.simple_insert(
                table="receipts_graph",
                values={
                    "room_id": "room_id",
                    "receipt_type": READ_PRIVATE_UNSTABLE,
                    "user_id": OUR_USER_ID,
                    "event_ids": "{}",
                    "data": "{}",
                },
            )
        )

        # Insert and run the background update
        self.get_success(
            self.store.db_pool.simple_insert(
                "background_updates",
                {
                    "update_name": _BackgroundUpdates.REMOVE_UNSTABLE_PRIVATE_READ_RECEIPTS,
                    "progress_json": "{}",
                },
            )
        )

        # ... and tell the DataStore that it hasn't finished all updates yet
        self.store.db_pool.updates._all_done = False

        # Now let's actually drive the updates to completion
        self.wait_for_background_updates()

        # Make sure the background update removed unstable private read receipt
        # from `receipts_linearized`
        receipts_linearized = self.get_success(
            self.store.db_pool.simple_select_list(
                table="receipts_linearized",
                keyvalues={"receipt_type": READ_PRIVATE_UNSTABLE},
                retcols={"room_id"},
            )
        )
        # Make sure the background update removed unstable private read receipt
        # from `receipts_graph`
        self.assertEqual(receipts_linearized, [])
        receipts_graph = self.get_success(
            self.store.db_pool.simple_select_list(
                table="receipts_graph",
                keyvalues={"receipt_type": READ_PRIVATE_UNSTABLE},
                retcols={"room_id"},
            )
        )
        self.assertEqual(receipts_graph, [])
