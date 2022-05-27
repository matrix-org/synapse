# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2021 The Matrix.org Foundation C.I.C.
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
import random
from typing import TYPE_CHECKING, Awaitable, Callable, Collection, List, Optional, Tuple

from synapse.replication.http.account_data import (
    ReplicationAddTagRestServlet,
    ReplicationRemoveTagRestServlet,
    ReplicationRoomAccountDataRestServlet,
    ReplicationUserAccountDataRestServlet,
)
from synapse.streams import EventSource
from synapse.types import JsonDict, StreamKeyType, UserID

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

ON_ACCOUNT_DATA_UPDATED_CALLBACK = Callable[
    [str, Optional[str], str, JsonDict], Awaitable
]


class AccountDataHandler:
    def __init__(self, hs: "HomeServer"):
        self._store = hs.get_datastores().main
        self._instance_name = hs.get_instance_name()
        self._notifier = hs.get_notifier()

        self._user_data_client = ReplicationUserAccountDataRestServlet.make_client(hs)
        self._room_data_client = ReplicationRoomAccountDataRestServlet.make_client(hs)
        self._add_tag_client = ReplicationAddTagRestServlet.make_client(hs)
        self._remove_tag_client = ReplicationRemoveTagRestServlet.make_client(hs)
        self._account_data_writers = hs.config.worker.writers.account_data

        self._on_account_data_updated_callbacks: List[
            ON_ACCOUNT_DATA_UPDATED_CALLBACK
        ] = []

    def register_module_callbacks(
        self, on_account_data_updated: Optional[ON_ACCOUNT_DATA_UPDATED_CALLBACK] = None
    ) -> None:
        """Register callbacks from modules."""
        if on_account_data_updated is not None:
            self._on_account_data_updated_callbacks.append(on_account_data_updated)

    async def _notify_modules(
        self,
        user_id: str,
        room_id: Optional[str],
        account_data_type: str,
        content: JsonDict,
    ) -> None:
        """Notifies modules about new account data changes.

        A change can be either a new account data type being added, or the content
        associated with a type being changed. Account data for a given type is removed by
        changing the associated content to an empty dictionary.

        Note that this is not called when the tags associated with a room change.

        Args:
            user_id: The user whose account data is changing.
            room_id: The ID of the room the account data change concerns, if any.
            account_data_type: The type of the account data.
            content: The content that is now associated with this type.
        """
        for callback in self._on_account_data_updated_callbacks:
            try:
                await callback(user_id, room_id, account_data_type, content)
            except Exception as e:
                logger.exception("Failed to run module callback %s: %s", callback, e)

    async def add_account_data_to_room(
        self, user_id: str, room_id: str, account_data_type: str, content: JsonDict
    ) -> int:
        """Add some account_data to a room for a user.

        Args:
            user_id: The user to add a tag for.
            room_id: The room to add a tag for.
            account_data_type: The type of account_data to add.
            content: A json object to associate with the tag.

        Returns:
            The maximum stream ID.
        """
        if self._instance_name in self._account_data_writers:
            max_stream_id = await self._store.add_account_data_to_room(
                user_id, room_id, account_data_type, content
            )

            self._notifier.on_new_event(
                StreamKeyType.ACCOUNT_DATA, max_stream_id, users=[user_id]
            )

            await self._notify_modules(user_id, room_id, account_data_type, content)

            return max_stream_id
        else:
            response = await self._room_data_client(
                instance_name=random.choice(self._account_data_writers),
                user_id=user_id,
                room_id=room_id,
                account_data_type=account_data_type,
                content=content,
            )
            return response["max_stream_id"]

    async def add_account_data_for_user(
        self, user_id: str, account_data_type: str, content: JsonDict
    ) -> int:
        """Add some global account_data for a user.

        Args:
            user_id: The user to add a tag for.
            account_data_type: The type of account_data to add.
            content: A json object to associate with the tag.

        Returns:
            The maximum stream ID.
        """

        if self._instance_name in self._account_data_writers:
            max_stream_id = await self._store.add_account_data_for_user(
                user_id, account_data_type, content
            )

            self._notifier.on_new_event(
                StreamKeyType.ACCOUNT_DATA, max_stream_id, users=[user_id]
            )

            await self._notify_modules(user_id, None, account_data_type, content)

            return max_stream_id
        else:
            response = await self._user_data_client(
                instance_name=random.choice(self._account_data_writers),
                user_id=user_id,
                account_data_type=account_data_type,
                content=content,
            )
            return response["max_stream_id"]

    async def add_tag_to_room(
        self, user_id: str, room_id: str, tag: str, content: JsonDict
    ) -> int:
        """Add a tag to a room for a user.

        Args:
            user_id: The user to add a tag for.
            room_id: The room to add a tag for.
            tag: The tag name to add.
            content: A json object to associate with the tag.

        Returns:
            The next account data ID.
        """
        if self._instance_name in self._account_data_writers:
            max_stream_id = await self._store.add_tag_to_room(
                user_id, room_id, tag, content
            )

            self._notifier.on_new_event(
                StreamKeyType.ACCOUNT_DATA, max_stream_id, users=[user_id]
            )
            return max_stream_id
        else:
            response = await self._add_tag_client(
                instance_name=random.choice(self._account_data_writers),
                user_id=user_id,
                room_id=room_id,
                tag=tag,
                content=content,
            )
            return response["max_stream_id"]

    async def remove_tag_from_room(self, user_id: str, room_id: str, tag: str) -> int:
        """Remove a tag from a room for a user.

        Returns:
            The next account data ID.
        """
        if self._instance_name in self._account_data_writers:
            max_stream_id = await self._store.remove_tag_from_room(
                user_id, room_id, tag
            )

            self._notifier.on_new_event(
                StreamKeyType.ACCOUNT_DATA, max_stream_id, users=[user_id]
            )
            return max_stream_id
        else:
            response = await self._remove_tag_client(
                instance_name=random.choice(self._account_data_writers),
                user_id=user_id,
                room_id=room_id,
                tag=tag,
            )
            return response["max_stream_id"]


class AccountDataEventSource(EventSource[int, JsonDict]):
    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastores().main

    def get_current_key(self, direction: str = "f") -> int:
        return self.store.get_max_account_data_stream_id()

    async def get_new_events(
        self,
        user: UserID,
        from_key: int,
        limit: Optional[int],
        room_ids: Collection[str],
        is_guest: bool,
        explicit_room_id: Optional[str] = None,
    ) -> Tuple[List[JsonDict], int]:
        user_id = user.to_string()
        last_stream_id = from_key

        current_stream_id = self.store.get_max_account_data_stream_id()

        results = []
        tags = await self.store.get_updated_tags(user_id, last_stream_id)

        for room_id, room_tags in tags.items():
            results.append(
                {"type": "m.tag", "content": {"tags": room_tags}, "room_id": room_id}
            )

        (
            account_data,
            room_account_data,
        ) = await self.store.get_updated_account_data_for_user(user_id, last_stream_id)

        for account_data_type, content in account_data.items():
            results.append({"type": account_data_type, "content": content})

        for room_id, account_data in room_account_data.items():
            for account_data_type, content in account_data.items():
                results.append(
                    {"type": account_data_type, "content": content, "room_id": room_id}
                )

        return results, current_stream_id
