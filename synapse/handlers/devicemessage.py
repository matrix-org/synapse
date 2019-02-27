# -*- coding: utf-8 -*-
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

import logging

from twisted.internet import defer

from synapse.api.errors import SynapseError
from synapse.types import UserID, get_domain_from_id
from synapse.util.stringutils import random_string

logger = logging.getLogger(__name__)


class DeviceMessageHandler(object):

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        self.store = hs.get_datastore()
        self.notifier = hs.get_notifier()
        self.is_mine = hs.is_mine
        self.federation = hs.get_federation_sender()

        hs.get_federation_registry().register_edu_handler(
            "m.direct_to_device", self.on_direct_to_device_edu
        )

    @defer.inlineCallbacks
    def on_direct_to_device_edu(self, origin, content):
        local_messages = {}
        sender_user_id = content["sender"]
        if origin != get_domain_from_id(sender_user_id):
            logger.warn(
                "Dropping device message from %r with spoofed sender %r",
                origin, sender_user_id
            )
        message_type = content["type"]
        message_id = content["message_id"]
        for user_id, by_device in content["messages"].items():
            # we use UserID.from_string to catch invalid user ids
            if not self.is_mine(UserID.from_string(user_id)):
                logger.warning("Request for keys for non-local user %s",
                               user_id)
                raise SynapseError(400, "Not a user here")

            messages_by_device = {
                device_id: {
                    "content": message_content,
                    "type": message_type,
                    "sender": sender_user_id,
                }
                for device_id, message_content in by_device.items()
            }
            if messages_by_device:
                local_messages[user_id] = messages_by_device

        stream_id = yield self.store.add_messages_from_remote_to_device_inbox(
            origin, message_id, local_messages
        )

        self.notifier.on_new_event(
            "to_device_key", stream_id, users=local_messages.keys()
        )

    @defer.inlineCallbacks
    def send_device_message(self, sender_user_id, message_type, messages):

        local_messages = {}
        remote_messages = {}
        for user_id, by_device in messages.items():
            # we use UserID.from_string to catch invalid user ids
            if self.is_mine(UserID.from_string(user_id)):
                messages_by_device = {
                    device_id: {
                        "content": message_content,
                        "type": message_type,
                        "sender": sender_user_id,
                    }
                    for device_id, message_content in by_device.items()
                }
                if messages_by_device:
                    local_messages[user_id] = messages_by_device
            else:
                destination = get_domain_from_id(user_id)
                remote_messages.setdefault(destination, {})[user_id] = by_device

        message_id = random_string(16)

        remote_edu_contents = {}
        for destination, messages in remote_messages.items():
            remote_edu_contents[destination] = {
                "messages": messages,
                "sender": sender_user_id,
                "type": message_type,
                "message_id": message_id,
            }

        stream_id = yield self.store.add_messages_to_device_inbox(
            local_messages, remote_edu_contents
        )

        self.notifier.on_new_event(
            "to_device_key", stream_id, users=local_messages.keys()
        )

        for destination in remote_messages.keys():
            # Enqueue a new federation transaction to send the new
            # device messages to each remote destination.
            self.federation.send_device_messages(destination)
