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
from typing import TYPE_CHECKING, Any, Dict

from synapse.api.errors import SynapseError
from synapse.logging.context import run_in_background
from synapse.logging.opentracing import (
    get_active_span_text_map,
    log_kv,
    set_tag,
    start_active_span,
)
from synapse.replication.http.devices import ReplicationUserDevicesResyncRestServlet
from synapse.types import JsonDict, UserID, get_domain_from_id
from synapse.util import json_encoder
from synapse.util.stringutils import random_string

if TYPE_CHECKING:
    from synapse.app.homeserver import HomeServer


logger = logging.getLogger(__name__)


class DeviceMessageHandler:
    def __init__(self, hs: "HomeServer"):
        """
        Args:
            hs: server
        """
        self.store = hs.get_datastore()
        self.notifier = hs.get_notifier()
        self.is_mine = hs.is_mine

        # We only need to poke the federation sender explicitly if its on the
        # same instance. Other federation sender instances will get notified by
        # `synapse.app.generic_worker.FederationSenderHandler` when it sees it
        # in the to-device replication stream.
        self.federation_sender = None
        if hs.should_send_federation():
            self.federation_sender = hs.get_federation_sender()

        # If we can handle the to device EDUs we do so, otherwise we route them
        # to the appropriate worker.
        if hs.get_instance_name() in hs.config.worker.writers.to_device:
            hs.get_federation_registry().register_edu_handler(
                "m.direct_to_device", self.on_direct_to_device_edu
            )
        else:
            hs.get_federation_registry().register_instances_for_edu(
                "m.direct_to_device",
                hs.config.worker.writers.to_device,
            )

        # The handler to call when we think a user's device list might be out of
        # sync. We do all device list resyncing on the master instance, so if
        # we're on a worker we hit the device resync replication API.
        if hs.config.worker.worker_app is None:
            self._user_device_resync = (
                hs.get_device_handler().device_list_updater.user_device_resync
            )
        else:
            self._user_device_resync = (
                ReplicationUserDevicesResyncRestServlet.make_client(hs)
            )

    async def on_direct_to_device_edu(self, origin: str, content: JsonDict) -> None:
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

            await self._check_for_unknown_devices(
                message_type, sender_user_id, by_device
            )

        stream_id = await self.store.add_messages_from_remote_to_device_inbox(
            origin, message_id, local_messages
        )

        self.notifier.on_new_event(
            "to_device_key", stream_id, users=local_messages.keys()
        )

    async def _check_for_unknown_devices(
        self,
        message_type: str,
        sender_user_id: str,
        by_device: Dict[str, Dict[str, Any]],
    ) -> None:
        """Checks inbound device messages for unknown remote devices, and if
        found marks the remote cache for the user as stale.
        """

        if message_type != "m.room_key_request":
            return

        # Get the sending device IDs
        requesting_device_ids = set()
        for message_content in by_device.values():
            device_id = message_content.get("requesting_device_id")
            requesting_device_ids.add(device_id)

        # Check if we are tracking the devices of the remote user.
        room_ids = await self.store.get_rooms_for_user(sender_user_id)
        if not room_ids:
            logger.info(
                "Received device message from remote device we don't"
                " share a room with: %s %s",
                sender_user_id,
                requesting_device_ids,
            )
            return

        # If we are tracking check that we know about the sending
        # devices.
        cached_devices = await self.store.get_cached_devices_for_user(sender_user_id)

        unknown_devices = requesting_device_ids - set(cached_devices)
        if unknown_devices:
            logger.info(
                "Received device message from remote device not in our cache: %s %s",
                sender_user_id,
                unknown_devices,
            )
            await self.store.mark_remote_user_device_cache_as_stale(sender_user_id)

            # Immediately attempt a resync in the background
            run_in_background(self._user_device_resync, user_id=sender_user_id)

    async def send_device_message(
        self,
        sender_user_id: str,
        message_type: str,
        messages: Dict[str, Dict[str, JsonDict]],
    ) -> None:
        set_tag("number_of_messages", len(messages))
        set_tag("sender", sender_user_id)
        local_messages = {}
        remote_messages = {}  # type: Dict[str, Dict[str, Dict[str, JsonDict]]]
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
                    "org.matrix.opentracing_context": json_encoder.encode(context),
                }

        log_kv({"local_messages": local_messages})
        stream_id = await self.store.add_messages_to_device_inbox(
            local_messages, remote_edu_contents
        )

        self.notifier.on_new_event(
            "to_device_key", stream_id, users=local_messages.keys()
        )

        log_kv({"remote_messages": remote_messages})
        if self.federation_sender:
            for destination in remote_messages.keys():
                # Enqueue a new federation transaction to send the new
                # device messages to each remote destination.
                self.federation_sender.send_device_messages(destination)
