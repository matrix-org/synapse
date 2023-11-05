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
from http import HTTPStatus
from typing import TYPE_CHECKING, Any, Dict, Optional

from synapse.api.constants import EduTypes, EventContentFields, ToDeviceEventTypes
from synapse.api.errors import Codes, SynapseError
from synapse.api.ratelimiting import Ratelimiter
from synapse.logging.context import run_in_background
from synapse.logging.opentracing import (
    SynapseTags,
    get_active_span_text_map,
    log_kv,
    set_tag,
)
from synapse.replication.http.devices import (
    ReplicationMultiUserDevicesResyncRestServlet,
)
from synapse.types import JsonDict, Requester, StreamKeyType, UserID, get_domain_from_id
from synapse.util import json_encoder
from synapse.util.stringutils import random_string

if TYPE_CHECKING:
    from synapse.server import HomeServer


logger = logging.getLogger(__name__)


class DeviceMessageHandler:
    def __init__(self, hs: "HomeServer"):
        """
        Args:
            hs: server
        """
        self.store = hs.get_datastores().main
        self.notifier = hs.get_notifier()
        self.is_mine = hs.is_mine
        if hs.config.experimental.msc3814_enabled:
            self.event_sources = hs.get_event_sources()
            self.device_handler = hs.get_device_handler()

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
                EduTypes.DIRECT_TO_DEVICE, self.on_direct_to_device_edu
            )
        else:
            hs.get_federation_registry().register_instances_for_edu(
                EduTypes.DIRECT_TO_DEVICE,
                hs.config.worker.writers.to_device,
            )

        # The handler to call when we think a user's device list might be out of
        # sync. We do all device list resyncing on the master instance, so if
        # we're on a worker we hit the device resync replication API.
        if hs.config.worker.worker_app is None:
            self._multi_user_device_resync = (
                hs.get_device_handler().device_list_updater.multi_user_device_resync
            )
        else:
            self._multi_user_device_resync = (
                ReplicationMultiUserDevicesResyncRestServlet.make_client(hs)
            )

        # a rate limiter for room key requests.  The keys are
        # (sending_user_id, sending_device_id).
        self._ratelimiter = Ratelimiter(
            store=self.store,
            clock=hs.get_clock(),
            cfg=hs.config.ratelimiting.rc_key_requests,
        )

    async def on_direct_to_device_edu(self, origin: str, content: JsonDict) -> None:
        """
        Handle receiving to-device messages from remote homeservers.

        Args:
            origin: The remote homeserver.
            content: The JSON dictionary containing the to-device messages.
        """
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
                logger.warning("To-device message to non-local user %s", user_id)
                raise SynapseError(400, "Not a user here")

            if not by_device:
                continue

            # Ratelimit key requests by the sending user.
            if message_type == ToDeviceEventTypes.RoomKeyRequest:
                allowed, _ = await self._ratelimiter.can_do_action(
                    None, (sender_user_id, None)
                )
                if not allowed:
                    logger.info(
                        "Dropping room_key_request from %s to %s due to rate limit",
                        sender_user_id,
                        user_id,
                    )
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

        # Add messages to the database.
        # Retrieve the stream id of the last-processed to-device message.
        last_stream_id = await self.store.add_messages_from_remote_to_device_inbox(
            origin, message_id, local_messages
        )

        # Notify listeners that there are new to-device messages to process,
        # handing them the latest stream id.
        self.notifier.on_new_event(
            StreamKeyType.TO_DEVICE, last_stream_id, users=local_messages.keys()
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
            await self.store.mark_remote_users_device_caches_as_stale((sender_user_id,))

            # Immediately attempt a resync in the background
            run_in_background(self._multi_user_device_resync, user_ids=[sender_user_id])

    async def send_device_message(
        self,
        requester: Requester,
        message_type: str,
        messages: Dict[str, Dict[str, JsonDict]],
    ) -> None:
        """
        Handle a request from a user to send to-device message(s).

        Args:
            requester: The user that is sending the to-device messages.
            message_type: The type of to-device messages that are being sent.
            messages: A dictionary containing recipients mapped to messages intended for them.
        """
        sender_user_id = requester.user.to_string()

        set_tag(SynapseTags.TO_DEVICE_TYPE, message_type)
        set_tag(SynapseTags.TO_DEVICE_SENDER, sender_user_id)
        local_messages = {}
        remote_messages: Dict[str, Dict[str, Dict[str, JsonDict]]] = {}
        for user_id, by_device in messages.items():
            # add an opentracing log entry for each message
            for device_id, message_content in by_device.items():
                log_kv(
                    {
                        "event": "send_to_device_message",
                        "user_id": user_id,
                        "device_id": device_id,
                        EventContentFields.TO_DEVICE_MSGID: message_content.get(
                            EventContentFields.TO_DEVICE_MSGID
                        ),
                    }
                )

            # Ratelimit local cross-user key requests by the sending device.
            if (
                message_type == ToDeviceEventTypes.RoomKeyRequest
                and user_id != sender_user_id
            ):
                allowed, _ = await self._ratelimiter.can_do_action(
                    requester, (sender_user_id, requester.device_id)
                )
                if not allowed:
                    log_kv({"message": f"dropping key requests to {user_id}"})
                    logger.info(
                        "Dropping room_key_request from %s to %s due to rate limit",
                        sender_user_id,
                        user_id,
                    )
                    continue

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

        context = get_active_span_text_map()

        remote_edu_contents = {}
        for destination, messages in remote_messages.items():
            # The EDU contains a "message_id" property which is used for
            # idempotence. Make up a random one.
            message_id = random_string(16)
            log_kv({"destination": destination, "message_id": message_id})

            remote_edu_contents[destination] = {
                "messages": messages,
                "sender": sender_user_id,
                "type": message_type,
                "message_id": message_id,
                "org.matrix.opentracing_context": json_encoder.encode(context),
            }

        # Add messages to the database.
        # Retrieve the stream id of the last-processed to-device message.
        last_stream_id = await self.store.add_messages_to_device_inbox(
            local_messages, remote_edu_contents
        )

        # Notify listeners that there are new to-device messages to process,
        # handing them the latest stream id.
        self.notifier.on_new_event(
            StreamKeyType.TO_DEVICE, last_stream_id, users=local_messages.keys()
        )

        if self.federation_sender:
            # Enqueue a new federation transaction to send the new
            # device messages to each remote destination.
            await self.federation_sender.send_device_messages(remote_messages.keys())

    async def get_events_for_dehydrated_device(
        self,
        requester: Requester,
        device_id: str,
        since_token: Optional[str],
        limit: int,
    ) -> JsonDict:
        """Fetches up to `limit` events sent to `device_id` starting from `since_token`
        and returns the new since token. If there are no more messages, returns an empty
        array.

        Args:
            requester: the user requesting the messages
            device_id: ID of the dehydrated device
            since_token: stream id to start from when fetching messages
            limit: the number of messages to fetch
        Returns:
            A dict containing the to-device messages, as well as a token that the client
            can provide in the next call to fetch the next batch of messages
        """

        user_id = requester.user.to_string()

        # only allow fetching messages for the dehydrated device id currently associated
        # with the user
        dehydrated_device = await self.device_handler.get_dehydrated_device(user_id)
        if dehydrated_device is None:
            raise SynapseError(
                HTTPStatus.FORBIDDEN,
                "No dehydrated device exists",
                Codes.FORBIDDEN,
            )

        dehydrated_device_id, _ = dehydrated_device
        if device_id != dehydrated_device_id:
            raise SynapseError(
                HTTPStatus.FORBIDDEN,
                "You may only fetch messages for your dehydrated device",
                Codes.FORBIDDEN,
            )

        since_stream_id = 0
        if since_token:
            if not since_token.startswith("d"):
                raise SynapseError(
                    HTTPStatus.BAD_REQUEST,
                    "from parameter %r has an invalid format" % (since_token,),
                    errcode=Codes.INVALID_PARAM,
                )

            try:
                since_stream_id = int(since_token[1:])
            except Exception:
                raise SynapseError(
                    HTTPStatus.BAD_REQUEST,
                    "from parameter %r has an invalid format" % (since_token,),
                    errcode=Codes.INVALID_PARAM,
                )

        to_token = self.event_sources.get_current_token().to_device_key

        messages, stream_id = await self.store.get_messages_for_device(
            user_id, device_id, since_stream_id, to_token, limit
        )

        for message in messages:
            # Remove the message id before sending to client
            message_id = message.pop("message_id", None)
            if message_id:
                set_tag(SynapseTags.TO_DEVICE_EDU_ID, message_id)

        logger.debug(
            "Returning %d to-device messages between %d and %d (current token: %d) for "
            "dehydrated device %s, user_id %s",
            len(messages),
            since_stream_id,
            stream_id,
            to_token,
            device_id,
            user_id,
        )

        return {
            "events": messages,
            "next_batch": f"d{stream_id}",
        }
