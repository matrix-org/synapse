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

from typing import TYPE_CHECKING, Iterator, Tuple

import attr

from synapse.handlers.account_data import AccountDataEventSource
from synapse.handlers.presence import PresenceEventSource
from synapse.handlers.receipts import ReceiptEventSource
from synapse.handlers.room import RoomEventSource
from synapse.handlers.typing import TypingNotificationEventSource
from synapse.logging.opentracing import trace
from synapse.streams import EventSource
from synapse.types import StreamToken

if TYPE_CHECKING:
    from synapse.server import HomeServer


@attr.s(frozen=True, slots=True, auto_attribs=True)
class _EventSourcesInner:
    room: RoomEventSource
    presence: PresenceEventSource
    typing: TypingNotificationEventSource
    receipt: ReceiptEventSource
    account_data: AccountDataEventSource

    def get_sources(self) -> Iterator[Tuple[str, EventSource]]:
        for attribute in attr.fields(_EventSourcesInner):
            yield attribute.name, getattr(self, attribute.name)


class EventSources:
    def __init__(self, hs: "HomeServer"):
        self.sources = _EventSourcesInner(
            # mypy thinks attribute.type is `Optional`, but we know it's never `None` here since
            # all the attributes of `_EventSourcesInner` are annotated.
            *(attribute.type(hs) for attribute in attr.fields(_EventSourcesInner))  # type: ignore[misc]
        )
        self.store = hs.get_datastores().main

    def get_current_token(self) -> StreamToken:
        push_rules_key = self.store.get_max_push_rules_stream_id()
        to_device_key = self.store.get_to_device_stream_token()
        device_list_key = self.store.get_device_stream_token()

        token = StreamToken(
            room_key=self.sources.room.get_current_key(),
            presence_key=self.sources.presence.get_current_key(),
            typing_key=self.sources.typing.get_current_key(),
            receipt_key=self.sources.receipt.get_current_key(),
            account_data_key=self.sources.account_data.get_current_key(),
            push_rules_key=push_rules_key,
            to_device_key=to_device_key,
            device_list_key=device_list_key,
            # Groups key is unused.
            groups_key=0,
        )
        return token

    @trace
    async def get_current_token_for_pagination(self, room_id: str) -> StreamToken:
        """Get the current token for a given room to be used to paginate
        events.

        The returned token does not have the current values for fields other
        than `room`, since they are not used during pagination.

        Returns:
            The current token for pagination.
        """
        token = StreamToken(
            room_key=await self.sources.room.get_current_key_for_room(room_id),
            presence_key=0,
            typing_key=0,
            receipt_key=0,
            account_data_key=0,
            push_rules_key=0,
            to_device_key=0,
            device_list_key=0,
            groups_key=0,
        )
        return token
