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
from http import HTTPStatus
from typing import Optional

from twisted.test.proto_helpers import MemoryReactor

import synapse.rest.admin
from synapse.api.constants import EduTypes, EventTypes, HistoryVisibility, ReceiptTypes
from synapse.rest.client import login, receipts, room, sync
from synapse.server import HomeServer
from synapse.types import JsonDict
from synapse.util import Clock

from tests import unittest


class ReceiptsTestCase(unittest.HomeserverTestCase):
    servlets = [
        login.register_servlets,
        receipts.register_servlets,
        synapse.rest.admin.register_servlets,
        room.register_servlets,
        sync.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.url = "/sync?since=%s"
        self.next_batch = "s0"

        # Register the first user
        self.user_id = self.register_user("kermit", "monkey")
        self.tok = self.login("kermit", "monkey")

        # Create the room
        self.room_id = self.helper.create_room_as(self.user_id, tok=self.tok)

        # Register the second user
        self.user2 = self.register_user("kermit2", "monkey")
        self.tok2 = self.login("kermit2", "monkey")

        # Join the second user
        self.helper.join(room=self.room_id, user=self.user2, tok=self.tok2)

    def test_send_receipt(self) -> None:
        # Send a message.
        res = self.helper.send(self.room_id, body="hello", tok=self.tok)

        # Send a read receipt
        channel = self.make_request(
            "POST",
            f"/rooms/{self.room_id}/receipt/{ReceiptTypes.READ}/{res['event_id']}",
            {},
            access_token=self.tok2,
        )
        self.assertEqual(channel.code, 200)
        self.assertNotEqual(self._get_read_receipt(), None)

    def test_send_receipt_unknown_event(self) -> None:
        """Receipts sent for unknown events are ignored to not break message retention."""
        # Attempt to send a receipt to an unknown room.
        channel = self.make_request(
            "POST",
            "/rooms/!abc:beep/receipt/m.read/$def",
            content={},
            access_token=self.tok2,
        )
        self.assertEqual(channel.code, 200, channel.result)
        self.assertIsNone(self._get_read_receipt())

        # Attempt to send a receipt to an unknown event.
        channel = self.make_request(
            "POST",
            f"/rooms/{self.room_id}/receipt/m.read/$def",
            content={},
            access_token=self.tok2,
        )
        self.assertEqual(channel.code, 200, channel.result)
        self.assertIsNone(self._get_read_receipt())

    def test_send_receipt_unviewable_event(self) -> None:
        """Receipts sent for unviewable events are errors."""
        # Create a room where new users can't see events from before their join
        # & send events into it.
        room_id = self.helper.create_room_as(
            self.user_id,
            tok=self.tok,
            extra_content={
                "preset": "private_chat",
                "initial_state": [
                    {
                        "content": {"history_visibility": HistoryVisibility.JOINED},
                        "state_key": "",
                        "type": EventTypes.RoomHistoryVisibility,
                    }
                ],
            },
        )
        res = self.helper.send(room_id, body="hello", tok=self.tok)

        # Attempt to send a receipt from the wrong user.
        channel = self.make_request(
            "POST",
            f"/rooms/{room_id}/receipt/{ReceiptTypes.READ}/{res['event_id']}",
            content={},
            access_token=self.tok2,
        )
        self.assertEqual(channel.code, 403, channel.result)

        # Join the user to the room, but they still can't see the event.
        self.helper.invite(room_id, self.user_id, self.user2, tok=self.tok)
        self.helper.join(room=room_id, user=self.user2, tok=self.tok2)

        channel = self.make_request(
            "POST",
            f"/rooms/{room_id}/receipt/{ReceiptTypes.READ}/{res['event_id']}",
            content={},
            access_token=self.tok2,
        )
        self.assertEqual(channel.code, 403, channel.result)

    def test_send_receipt_invalid_room_id(self) -> None:
        channel = self.make_request(
            "POST",
            "/rooms/not-a-room-id/receipt/m.read/$def",
            content={},
            access_token=self.tok,
        )
        self.assertEqual(channel.code, 400, channel.result)
        self.assertEqual(
            channel.json_body["error"], "A valid room ID and event ID must be specified"
        )

    def test_send_receipt_invalid_event_id(self) -> None:
        channel = self.make_request(
            "POST",
            "/rooms/!abc:beep/receipt/m.read/not-an-event-id",
            content={},
            access_token=self.tok,
        )
        self.assertEqual(channel.code, 400, channel.result)
        self.assertEqual(
            channel.json_body["error"], "A valid room ID and event ID must be specified"
        )

    def test_send_receipt_invalid_receipt_type(self) -> None:
        channel = self.make_request(
            "POST",
            "/rooms/!abc:beep/receipt/invalid-receipt-type/$def",
            content={},
            access_token=self.tok,
        )
        self.assertEqual(channel.code, 400, channel.result)

    def test_private_read_receipts(self) -> None:
        # Send a message as the first user
        res = self.helper.send(self.room_id, body="hello", tok=self.tok)

        # Send a private read receipt to tell the server the first user's message was read
        channel = self.make_request(
            "POST",
            f"/rooms/{self.room_id}/receipt/{ReceiptTypes.READ_PRIVATE}/{res['event_id']}",
            {},
            access_token=self.tok2,
        )
        self.assertEqual(channel.code, 200)

        # Test that the first user can't see the other user's private read receipt
        self.assertIsNone(self._get_read_receipt())

    def test_public_receipt_can_override_private(self) -> None:
        """
        Sending a public read receipt to the same event which has a private read
        receipt should cause that receipt to become public.
        """
        # Send a message as the first user
        res = self.helper.send(self.room_id, body="hello", tok=self.tok)

        # Send a private read receipt
        channel = self.make_request(
            "POST",
            f"/rooms/{self.room_id}/receipt/{ReceiptTypes.READ_PRIVATE}/{res['event_id']}",
            {},
            access_token=self.tok2,
        )
        self.assertEqual(channel.code, 200)
        self.assertIsNone(self._get_read_receipt())

        # Send a public read receipt
        channel = self.make_request(
            "POST",
            f"/rooms/{self.room_id}/receipt/{ReceiptTypes.READ}/{res['event_id']}",
            {},
            access_token=self.tok2,
        )
        self.assertEqual(channel.code, 200)

        # Test that we did override the private read receipt
        self.assertNotEqual(self._get_read_receipt(), None)

    def test_private_receipt_cannot_override_public(self) -> None:
        """
        Sending a private read receipt to the same event which has a public read
        receipt should cause no change.
        """
        # Send a message as the first user
        res = self.helper.send(self.room_id, body="hello", tok=self.tok)

        # Send a public read receipt
        channel = self.make_request(
            "POST",
            f"/rooms/{self.room_id}/receipt/{ReceiptTypes.READ}/{res['event_id']}",
            {},
            access_token=self.tok2,
        )
        self.assertEqual(channel.code, 200)
        self.assertNotEqual(self._get_read_receipt(), None)

        # Send a private read receipt
        channel = self.make_request(
            "POST",
            f"/rooms/{self.room_id}/receipt/{ReceiptTypes.READ_PRIVATE}/{res['event_id']}",
            {},
            access_token=self.tok2,
        )
        self.assertEqual(channel.code, 200)

        # Test that we didn't override the public read receipt
        self.assertIsNone(self._get_read_receipt())

    def test_read_receipt_with_empty_body_is_rejected(self) -> None:
        # Send a message as the first user
        res = self.helper.send(self.room_id, body="hello", tok=self.tok)

        # Send a read receipt for this message with an empty body
        channel = self.make_request(
            "POST",
            f"/rooms/{self.room_id}/receipt/m.read/{res['event_id']}",
            access_token=self.tok2,
        )
        self.assertEqual(channel.code, HTTPStatus.BAD_REQUEST)
        self.assertEqual(channel.json_body["errcode"], "M_NOT_JSON", channel.json_body)

    def _get_read_receipt(self) -> Optional[JsonDict]:
        """Syncs and returns the read receipt."""

        # Checks if event is a read receipt
        def is_read_receipt(event: JsonDict) -> bool:
            return event["type"] == EduTypes.RECEIPT

        # Sync
        channel = self.make_request(
            "GET",
            self.url % self.next_batch,
            access_token=self.tok,
        )
        self.assertEqual(channel.code, 200)

        # Store the next batch for the next request.
        self.next_batch = channel.json_body["next_batch"]

        if channel.json_body.get("rooms", None) is None:
            return None

        # Return the read receipt
        ephemeral_events = channel.json_body["rooms"]["join"][self.room_id][
            "ephemeral"
        ]["events"]
        receipt_event = filter(is_read_receipt, ephemeral_events)
        return next(receipt_event, None)
