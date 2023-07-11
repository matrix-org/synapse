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
from twisted.test.proto_helpers import MemoryReactor

import synapse.rest.admin
from synapse.rest.client import login, receipts, register
from synapse.server import HomeServer
from synapse.util import Clock

from tests import unittest


class ReceiptsTestCase(unittest.HomeserverTestCase):
    servlets = [
        login.register_servlets,
        register.register_servlets,
        receipts.register_servlets,
        synapse.rest.admin.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.owner = self.register_user("owner", "pass")
        self.owner_tok = self.login("owner", "pass")

    def test_send_receipt(self) -> None:
        channel = self.make_request(
            "POST",
            "/rooms/!abc:beep/receipt/m.read/$def",
            content={},
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 200, channel.result)

    def test_send_receipt_invalid_room_id(self) -> None:
        channel = self.make_request(
            "POST",
            "/rooms/not-a-room-id/receipt/m.read/$def",
            content={},
            access_token=self.owner_tok,
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
            access_token=self.owner_tok,
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
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 400, channel.result)
