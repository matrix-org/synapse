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


from twisted.internet import defer

from synapse.api.constants import EventTypes


class EventInjector:
    def __init__(self, hs):
        self.hs = hs
        self.store = hs.get_datastore()
        self.message_handler = hs.get_handlers().message_handler
        self.event_builder_factory = hs.get_event_builder_factory()

    @defer.inlineCallbacks
    def create_room(self, room):
        builder = self.event_builder_factory.new({
            "type": EventTypes.Create,
            "sender": "",
            "room_id": room.to_string(),
            "content": {},
        })

        event, context = yield self.message_handler._create_new_client_event(
            builder
        )

        yield self.store.persist_event(event, context)

    @defer.inlineCallbacks
    def inject_room_member(self, room, user, membership):
        builder = self.event_builder_factory.new({
            "type": EventTypes.Member,
            "sender": user.to_string(),
            "state_key": user.to_string(),
            "room_id": room.to_string(),
            "content": {"membership": membership},
        })

        event, context = yield self.message_handler._create_new_client_event(
            builder
        )

        yield self.store.persist_event(event, context)

        defer.returnValue(event)

    @defer.inlineCallbacks
    def inject_message(self, room, user, body):
        builder = self.event_builder_factory.new({
            "type": EventTypes.Message,
            "sender": user.to_string(),
            "state_key": user.to_string(),
            "room_id": room.to_string(),
            "content": {"body": body, "msgtype": u"message"},
        })

        event, context = yield self.message_handler._create_new_client_event(
            builder
        )

        yield self.store.persist_event(event, context)
