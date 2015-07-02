# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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

"""Contains handlers for federation events."""

from ._base import BaseHandler

from twisted.internet import defer

from synapse.util.logcontext import PreserveLoggingContext

import logging


logger = logging.getLogger(__name__)


class ReceiptsHandler(BaseHandler):
    def __init__(self, hs):
        super(ReceiptsHandler, self).__init__(hs)

        self.federation.register_edu_handler(
            "m.receipt", self._received_remote_receipt
        )

        self._latest_serial = 0

    @defer.inlineCallbacks
    def received_client_receipt(self, room_id, receipt_type, user_id,
                                event_id):
        # 1. Persist.
        # 2. Notify local clients
        # 3. Notify remote servers

        receipt = {
            "room_id": room_id,
            "receipt_type": receipt_type,
            "user_id": user_id,
            "event_ids": [event_id],
        }

        yield self._handle_new_receipts([receipt])
        self._push_remotes([receipt])

    @defer.inlineCallbacks
    def _received_remote_receipt(self, origin, content):
        receipts = [
            {
                "room_id": room_id,
                "receipt_type": receipt_type,
                "user_id": user_id,
                "event_ids": [event_id],
            }
            for room_id, room_values in content.items()
            for event_id, ev_values in room_values.items()
            for receipt_type, users in ev_values.items()
            for user_id in users
        ]

        yield self._handle_new_receipts(receipts)

    @defer.inlineCallbacks
    def _handle_new_receipts(self, receipts):
        for receipt in receipts:
            room_id = receipt["room_id"]
            receipt_type = receipt["receipt_type"]
            user_id = receipt["user_id"]
            event_ids = receipt["event_ids"]

            stream_id, max_persisted_id = yield self.store.insert_receipt(
                room_id, receipt_type, user_id, event_ids,
            )

            # TODO: Use max_persisted_id

            self._latest_serial = max(self._latest_serial, stream_id)

            with PreserveLoggingContext():
                self.notifier.on_new_event(
                    "recei[t_key", self._latest_serial, rooms=[room_id]
                )

            localusers = set()
            remotedomains = set()

            rm_handler = self.homeserver.get_handlers().room_member_handler
            yield rm_handler.fetch_room_distributions_into(
                room_id, localusers=localusers, remotedomains=remotedomains
            )

            receipt["remotedomains"] = remotedomains

            self.notifier.on_new_event(
                "receipt_key", self._latest_room_serial, rooms=[room_id]
            )

    def _push_remotes(self, receipts):
        # TODO: Some of this stuff should be coallesced.
        for receipt in receipts:
            room_id = receipt["room_id"]
            receipt_type = receipt["receipt_type"]
            user_id = receipt["user_id"]
            event_ids = receipt["event_ids"]
            remotedomains = receipt["remotedomains"]

            for domain in remotedomains:
                self.federation.send_edu(
                    destination=domain,
                    edu_type="m.receipt",
                    content={
                        room_id: {
                            event_id: {
                                receipt_type: [user_id]
                            }
                            for event_id in event_ids
                        },
                    },
                )
