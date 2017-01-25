# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

from twisted.internet import defer

from synapse.types import StreamToken

from synapse.handlers.presence import PresenceEventSource
from synapse.handlers.room import RoomEventSource
from synapse.handlers.typing import TypingNotificationEventSource
from synapse.handlers.receipts import ReceiptEventSource
from synapse.handlers.account_data import AccountDataEventSource


class EventSources(object):
    SOURCE_TYPES = {
        "room": RoomEventSource,
        "presence": PresenceEventSource,
        "typing": TypingNotificationEventSource,
        "receipt": ReceiptEventSource,
        "account_data": AccountDataEventSource,
    }

    def __init__(self, hs):
        self.sources = {
            name: cls(hs)
            for name, cls in EventSources.SOURCE_TYPES.items()
        }
        self.store = hs.get_datastore()

    @defer.inlineCallbacks
    def get_current_token(self):
        push_rules_key, _ = self.store.get_push_rules_stream_token()
        to_device_key = self.store.get_to_device_stream_token()
        device_list_key = self.store.get_device_stream_token()

        token = StreamToken(
            room_key=(
                yield self.sources["room"].get_current_key()
            ),
            presence_key=(
                yield self.sources["presence"].get_current_key()
            ),
            typing_key=(
                yield self.sources["typing"].get_current_key()
            ),
            receipt_key=(
                yield self.sources["receipt"].get_current_key()
            ),
            account_data_key=(
                yield self.sources["account_data"].get_current_key()
            ),
            push_rules_key=push_rules_key,
            to_device_key=to_device_key,
            device_list_key=device_list_key,
        )
        defer.returnValue(token)

    @defer.inlineCallbacks
    def get_current_token_for_room(self, room_id):
        push_rules_key, _ = self.store.get_push_rules_stream_token()
        to_device_key = self.store.get_to_device_stream_token()
        device_list_key = self.store.get_device_stream_token()

        token = StreamToken(
            room_key=(
                yield self.sources["room"].get_current_key_for_room(room_id)
            ),
            presence_key=(
                yield self.sources["presence"].get_current_key()
            ),
            typing_key=(
                yield self.sources["typing"].get_current_key()
            ),
            receipt_key=(
                yield self.sources["receipt"].get_current_key()
            ),
            account_data_key=(
                yield self.sources["account_data"].get_current_key()
            ),
            push_rules_key=push_rules_key,
            to_device_key=to_device_key,
            device_list_key=device_list_key,
        )
        defer.returnValue(token)
