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

from canonicaljson import json

from twisted.internet import defer

import synapse
from synapse.api.errors import SynapseError
from synapse.logging.opentracing import (
    get_active_span_text_map,
    log_kv,
    set_tag,
    start_active_span,
)
from synapse.types import UserID, get_domain_from_id
from synapse.util.stringutils import random_string

logger = logging.getLogger(__name__)

device_list_debugging_logger = logging.getLogger("synapse.devices.DEBUG_TRACKING")


class DeviceMessageHandler(object):
    def __init__(self, hs: "synapse.server.HomeServer"):
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
            logger.warning(
                "Dropping device message from %r with spoofed sender %r",
                origin,
                sender_user_id,
            )
        message_type = content["type"]
        message_id = content["message_id"]
        for user_id, by_device in content["messages"].items():
            # we use UserID.from_string to catch invalid user ids
            if not self.is_mine(UserID.from_string(user_id)):
                logger.warning("Request for keys for non-local user %s", user_id)
                raise SynapseError(400, "Not a user here")

            if not by_device:
                continue

            messages_by_device = {
                device_id: {
                    "content": message_content,
                    "type": message_type,
                    "sender": sender_user_id,
                }
                for device_id, message_content in by_device.items()
            }
            local_messages[user_id] = messages_by_device

            if (
                device_list_debugging_logger.isEnabledFor(logging.INFO)
                and message_type == "m.room_key_request"
            ):
                # If we get a request to get keys then may mean the recipient
                # didn't know about the sender's device (or might just mean
                # things are being a bit slow to propogate).
                received_devices = set(by_device)
                sender_key = list(by_device.values())[0].get("sender_key", "<unknown>")
                device_list_debugging_logger.info(
                    "Received room_key request direct message (%s, %s) from %s (%s) to %s (%s).",
                    message_type,
                    message_id,
                    sender_user_id,
                    sender_key,
                    user_id,
                    received_devices,
                )
            elif device_list_debugging_logger.isEnabledFor(logging.INFO):
                # We expect the sending user to send the message to all the devices
                # to the user, if they don't then that is potentially suspicious and
                # so we log for debugging purposes.

                expected_devices = yield self.store.get_devices_by_user(user_id)
                expected_devices = set(expected_devices)
                received_devices = set(by_device)
                if received_devices != {"*"} and received_devices != expected_devices:
                    # Devices that the remote didn't send to
                    missed = expected_devices - received_devices

                    # Devices the remote sent to that we don't know bout
                    extraneous = received_devices - expected_devices

                    # We try and pull out the `sender_key` from the first message,
                    # if it has one. This just helps figure out which device the
                    # message came from.
                    sender_key = list(by_device.values())[0].get(
                        "sender_key", "<unknown>"
                    )

                    device_list_debugging_logger.info(
                        "Received direct message (%s, %s) from %s (%s) to %s with mismatched devices."
                        " Missing: %s, extraneous: %s",
                        message_type,
                        message_id,
                        sender_user_id,
                        sender_key,
                        user_id,
                        missed,
                        extraneous,
                    )

        stream_id = yield self.store.add_messages_from_remote_to_device_inbox(
            origin, message_id, local_messages
        )

        self.notifier.on_new_event(
            "to_device_key", stream_id, users=local_messages.keys()
        )

    @defer.inlineCallbacks
    def send_device_message(self, sender_user_id, message_type, messages):
        set_tag("number_of_messages", len(messages))
        set_tag("sender", sender_user_id)
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

        context = get_active_span_text_map()

        remote_edu_contents = {}
        for destination, messages in remote_messages.items():
            with start_active_span("to_device_for_user"):
                set_tag("destination", destination)
                remote_edu_contents[destination] = {
                    "messages": messages,
                    "sender": sender_user_id,
                    "type": message_type,
                    "message_id": message_id,
                    "org.matrix.opentracing_context": json.dumps(context),
                }

        log_kv({"local_messages": local_messages})
        stream_id = yield self.store.add_messages_to_device_inbox(
            local_messages, remote_edu_contents
        )

        self.notifier.on_new_event(
            "to_device_key", stream_id, users=local_messages.keys()
        )

        log_kv({"remote_messages": remote_messages})
        for destination in remote_messages.keys():
            # Enqueue a new federation transaction to send the new
            # device messages to each remote destination.
            self.federation.send_device_messages(destination)
