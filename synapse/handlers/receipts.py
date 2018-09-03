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

from twisted.internet import defer

from synapse.types import get_domain_from_id
from synapse.util import logcontext

from ._base import BaseHandler

logger = logging.getLogger(__name__)


class ReceiptsHandler(BaseHandler):
    def __init__(self, hs):
        super(ReceiptsHandler, self).__init__(hs)

        self.server_name = hs.config.server_name
        self.store = hs.get_datastore()
        self.hs = hs
        self.federation = hs.get_federation_sender()
        hs.get_federation_registry().register_edu_handler(
            "m.receipt", self._received_remote_receipt
        )
        self.clock = self.hs.get_clock()
        self.state = hs.get_state_handler()

    @defer.inlineCallbacks
    def received_client_receipt(self, room_id, receipt_type, user_id,
                                event_id):
        """Called when a client tells us a local user has read up to the given
        event_id in the room.
        """
        receipt = {
            "room_id": room_id,
            "receipt_type": receipt_type,
            "user_id": user_id,
            "event_ids": [event_id],
            "data": {
                "ts": int(self.clock.time_msec()),
            }
        }

        is_new = yield self._handle_new_receipts([receipt])

        if is_new:
            # fire off a process in the background to send the receipt to
            # remote servers
            self._push_remotes([receipt])

    @defer.inlineCallbacks
    def _received_remote_receipt(self, origin, content):
        """Called when we receive an EDU of type m.receipt from a remote HS.
        """
        receipts = [
            {
                "room_id": room_id,
                "receipt_type": receipt_type,
                "user_id": user_id,
                "event_ids": user_values["event_ids"],
                "data": user_values.get("data", {}),
            }
            for room_id, room_values in content.items()
            for receipt_type, users in room_values.items()
            for user_id, user_values in users.items()
        ]

        yield self._handle_new_receipts(receipts)

    @defer.inlineCallbacks
    def _handle_new_receipts(self, receipts):
        """Takes a list of receipts, stores them and informs the notifier.
        """
        min_batch_id = None
        max_batch_id = None

        for receipt in receipts:
            room_id = receipt["room_id"]
            receipt_type = receipt["receipt_type"]
            user_id = receipt["user_id"]
            event_ids = receipt["event_ids"]
            data = receipt["data"]

            res = yield self.store.insert_receipt(
                room_id, receipt_type, user_id, event_ids, data
            )

            if not res:
                # res will be None if this read receipt is 'old'
                continue

            stream_id, max_persisted_id = res

            if min_batch_id is None or stream_id < min_batch_id:
                min_batch_id = stream_id
            if max_batch_id is None or max_persisted_id > max_batch_id:
                max_batch_id = max_persisted_id

        if min_batch_id is None:
            # no new receipts
            defer.returnValue(False)

        affected_room_ids = list(set([r["room_id"] for r in receipts]))

        self.notifier.on_new_event(
            "receipt_key", max_batch_id, rooms=affected_room_ids
        )
        # Note that the min here shouldn't be relied upon to be accurate.
        self.hs.get_pusherpool().on_new_receipts(
            min_batch_id, max_batch_id, affected_room_ids,
        )

        defer.returnValue(True)

    @logcontext.preserve_fn   # caller should not yield on this
    @defer.inlineCallbacks
    def _push_remotes(self, receipts):
        """Given a list of receipts, works out which remote servers should be
        poked and pokes them.
        """
        try:
            # TODO: Some of this stuff should be coallesced.
            for receipt in receipts:
                room_id = receipt["room_id"]
                receipt_type = receipt["receipt_type"]
                user_id = receipt["user_id"]
                event_ids = receipt["event_ids"]
                data = receipt["data"]

                users = yield self.state.get_current_user_in_room(room_id)
                remotedomains = set(get_domain_from_id(u) for u in users)
                remotedomains = remotedomains.copy()
                remotedomains.discard(self.server_name)

                logger.debug("Sending receipt to: %r", remotedomains)

                for domain in remotedomains:
                    self.federation.send_edu(
                        destination=domain,
                        edu_type="m.receipt",
                        content={
                            room_id: {
                                receipt_type: {
                                    user_id: {
                                        "event_ids": event_ids,
                                        "data": data,
                                    }
                                }
                            },
                        },
                        key=(room_id, receipt_type, user_id),
                    )
        except Exception:
            logger.exception("Error pushing receipts to remote servers")

    @defer.inlineCallbacks
    def get_receipts_for_room(self, room_id, to_key):
        """Gets all receipts for a room, upto the given key.
        """
        result = yield self.store.get_linearized_receipts_for_room(
            room_id,
            to_key=to_key,
        )

        if not result:
            defer.returnValue([])

        defer.returnValue(result)


class ReceiptEventSource(object):
    def __init__(self, hs):
        self.store = hs.get_datastore()

    @defer.inlineCallbacks
    def get_new_events(self, from_key, room_ids, **kwargs):
        from_key = int(from_key)
        to_key = yield self.get_current_key()

        if from_key == to_key:
            defer.returnValue(([], to_key))

        events = yield self.store.get_linearized_receipts_for_rooms(
            room_ids,
            from_key=from_key,
            to_key=to_key,
        )

        defer.returnValue((events, to_key))

    def get_current_key(self, direction='f'):
        return self.store.get_max_receipt_stream_id()

    @defer.inlineCallbacks
    def get_pagination_rows(self, user, config, key):
        to_key = int(config.from_key)

        if config.to_key:
            from_key = int(config.to_key)
        else:
            from_key = None

        room_ids = yield self.store.get_rooms_for_user(user.to_string())
        events = yield self.store.get_linearized_receipts_for_rooms(
            room_ids,
            from_key=from_key,
            to_key=to_key,
        )

        defer.returnValue((events, to_key))
