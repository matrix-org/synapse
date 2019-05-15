# -*- coding: utf-8 -*-
# Copyright 2019 New Vector Ltd
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

from mock import Mock

from twisted.internet import defer

from synapse.types import ReadReceipt

from tests.unittest import HomeserverTestCase


class FederationSenderTestCases(HomeserverTestCase):
    def make_homeserver(self, reactor, clock):
        return super(FederationSenderTestCases, self).setup_test_homeserver(
            state_handler=Mock(spec=["get_current_hosts_in_room"]),
            federation_transport_client=Mock(spec=["send_transaction"]),
        )

    def test_send_receipts(self):
        mock_state_handler = self.hs.get_state_handler()
        mock_state_handler.get_current_hosts_in_room.return_value = ["test", "host2"]

        mock_send_transaction = (
            self.hs.get_federation_transport_client().send_transaction
        )
        mock_send_transaction.return_value = defer.succeed({})

        sender = self.hs.get_federation_sender()
        receipt = ReadReceipt(
            "room_id", "m.read", "user_id", ["event_id"], {"ts": 1234}
        )
        self.successResultOf(sender.send_read_receipt(receipt))

        self.pump()

        # expect a call to send_transaction
        mock_send_transaction.assert_called_once()
        json_cb = mock_send_transaction.call_args[0][1]
        data = json_cb()
        self.assertEqual(
            data['edus'],
            [
                {
                    'edu_type': 'm.receipt',
                    'content': {
                        'room_id': {
                            'm.read': {
                                'user_id': {
                                    'event_ids': ['event_id'],
                                    'data': {'ts': 1234},
                                }
                            }
                        }
                    },
                }
            ],
        )

    def test_send_receipts_with_backoff(self):
        """Send two receipts in quick succession; the second should be flushed, but
        only after 20ms"""
        mock_state_handler = self.hs.get_state_handler()
        mock_state_handler.get_current_hosts_in_room.return_value = ["test", "host2"]

        mock_send_transaction = (
            self.hs.get_federation_transport_client().send_transaction
        )
        mock_send_transaction.return_value = defer.succeed({})

        sender = self.hs.get_federation_sender()
        receipt = ReadReceipt(
            "room_id", "m.read", "user_id", ["event_id"], {"ts": 1234}
        )
        self.successResultOf(sender.send_read_receipt(receipt))

        self.pump()

        # expect a call to send_transaction
        mock_send_transaction.assert_called_once()
        json_cb = mock_send_transaction.call_args[0][1]
        data = json_cb()
        self.assertEqual(
            data['edus'],
            [
                {
                    'edu_type': 'm.receipt',
                    'content': {
                        'room_id': {
                            'm.read': {
                                'user_id': {
                                    'event_ids': ['event_id'],
                                    'data': {'ts': 1234},
                                }
                            }
                        }
                    },
                }
            ],
        )
        mock_send_transaction.reset_mock()

        # send the second RR
        receipt = ReadReceipt(
            "room_id", "m.read", "user_id", ["other_id"], {"ts": 1234}
        )
        self.successResultOf(sender.send_read_receipt(receipt))
        self.pump()
        mock_send_transaction.assert_not_called()

        self.reactor.advance(19)
        mock_send_transaction.assert_not_called()

        self.reactor.advance(10)
        mock_send_transaction.assert_called_once()
        json_cb = mock_send_transaction.call_args[0][1]
        data = json_cb()
        self.assertEqual(
            data['edus'],
            [
                {
                    'edu_type': 'm.receipt',
                    'content': {
                        'room_id': {
                            'm.read': {
                                'user_id': {
                                    'event_ids': ['other_id'],
                                    'data': {'ts': 1234},
                                }
                            }
                        }
                    },
                }
            ],
        )
