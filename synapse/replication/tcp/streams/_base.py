# -*- coding: utf-8 -*-
# Copyright 2017 Vector Creations Ltd
# Copyright 2019 New Vector Ltd
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

import heapq
import logging
from collections import namedtuple
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    List,
    Optional,
    Tuple,
    TypeVar,
)

import attr

from synapse.replication.http.streams import ReplicationGetStreamUpdates

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

# the number of rows to request from an update_function.
_STREAM_UPDATE_TARGET_ROW_COUNT = 100


# Some type aliases to make things a bit easier.

# A stream position token
Token = int

# The type of a stream update row, after JSON deserialisation, but before
# parsing with Stream.parse_row (which turns it into a `ROW_TYPE`). Normally it's
# just a row from a database query, though this is dependent on the stream in question.
#
StreamRow = TypeVar("StreamRow", bound=Tuple)

# The type returned by the update_function of a stream, as well as get_updates(),
# get_updates_since, etc.
#
# It consists of a triplet `(updates, new_last_token, limited)`, where:
#   * `updates` is a list of `(token, row)` entries.
#   * `new_last_token` is the new position in stream.
#   * `limited` is whether there are more updates to fetch.
#
StreamUpdateResult = Tuple[List[Tuple[Token, StreamRow]], Token, bool]

# The type of an update_function for a stream
#
# The arguments are:
#
#  * instance_name: the writer of the stream
#  * from_token: the previous stream token: the starting point for fetching the
#    updates
#  * to_token: the new stream token: the point to get updates up to
#  * target_row_count: a target for the number of rows to be returned.
#
# The update_function is expected to return up to _approximately_ target_row_count rows.
# If there are more updates available, it should set `limited` in the result, and
# it will be called again to get the next batch.
#
UpdateFunction = Callable[[str, Token, Token, int], Awaitable[StreamUpdateResult]]


class Stream:
    """Base class for the streams.

    Provides a `get_updates()` function that returns new updates since the last
    time it was called.
    """

    NAME = None  # type: str  # The name of the stream
    # The type of the row. Used by the default impl of parse_row.
    ROW_TYPE = None  # type: Any

    @classmethod
    def parse_row(cls, row: StreamRow):
        """Parse a row received over replication

        By default, assumes that the row data is an array object and passes its contents
        to the constructor of the ROW_TYPE for this stream.

        Args:
            row: row data from the incoming RDATA command, after json decoding

        Returns:
            ROW_TYPE object for this stream
        """
        return cls.ROW_TYPE(*row)

    def __init__(
        self,
        local_instance_name: str,
        current_token_function: Callable[[str], Token],
        update_function: UpdateFunction,
    ):
        """Instantiate a Stream

        `current_token_function` and `update_function` are callbacks which
        should be implemented by subclasses.

        `current_token_function` takes an instance name, which is a writer to
        the stream, and returns the position in the stream of the writer (as
        viewed from the current process). On the writer process this is where
        the writer has successfully written up to, whereas on other processes
        this is the position which we have received updates up to over
        replication. (Note that most streams have a single writer and so their
        implementations ignore the instance name passed in).

        `update_function` is called to get updates for this stream between a
        pair of stream tokens. See the `UpdateFunction` type definition for more
        info.

        Args:
            local_instance_name: The instance name of the current process
            current_token_function: callback to get the current token, as above
            update_function: callback go get stream updates, as above
        """
        self.local_instance_name = local_instance_name
        self.current_token = current_token_function
        self.update_function = update_function

        # The token from which we last asked for updates
        self.last_token = self.current_token(self.local_instance_name)

    def discard_updates_and_advance(self):
        """Called when the stream should advance but the updates would be discarded,
        e.g. when there are no currently connected workers.
        """
        self.last_token = self.current_token(self.local_instance_name)

    async def get_updates(self) -> StreamUpdateResult:
        """Gets all updates since the last time this function was called (or
        since the stream was constructed if it hadn't been called before).

        Returns:
            A triplet `(updates, new_last_token, limited)`, where `updates` is
            a list of `(token, row)` entries, `new_last_token` is the new
            position in stream, and `limited` is whether there are more updates
            to fetch.
        """
        current_token = self.current_token(self.local_instance_name)
        updates, current_token, limited = await self.get_updates_since(
            self.local_instance_name, self.last_token, current_token
        )
        self.last_token = current_token

        return updates, current_token, limited

    async def get_updates_since(
        self, instance_name: str, from_token: Token, upto_token: Token
    ) -> StreamUpdateResult:
        """Like get_updates except allows specifying from when we should
        stream updates

        Returns:
            A triplet `(updates, new_last_token, limited)`, where `updates` is
            a list of `(token, row)` entries, `new_last_token` is the new
            position in stream, and `limited` is whether there are more updates
            to fetch.
        """

        from_token = int(from_token)

        if from_token == upto_token:
            return [], upto_token, False

        updates, upto_token, limited = await self.update_function(
            instance_name,
            from_token,
            upto_token,
            _STREAM_UPDATE_TARGET_ROW_COUNT,
        )
        return updates, upto_token, limited


def current_token_without_instance(
    current_token: Callable[[], int]
) -> Callable[[str], int]:
    """Takes a current token callback function for a single writer stream
    that doesn't take an instance name parameter and wraps it in a function that
    does accept an instance name parameter but ignores it.
    """
    return lambda instance_name: current_token()


def make_http_update_function(hs, stream_name: str) -> UpdateFunction:
    """Makes a suitable function for use as an `update_function` that queries
    the master process for updates.
    """

    client = ReplicationGetStreamUpdates.make_client(hs)

    async def update_function(
        instance_name: str, from_token: int, upto_token: int, limit: int
    ) -> StreamUpdateResult:
        result = await client(
            instance_name=instance_name,
            stream_name=stream_name,
            from_token=from_token,
            upto_token=upto_token,
        )
        return result["updates"], result["upto_token"], result["limited"]

    return update_function


class BackfillStream(Stream):
    """We fetched some old events and either we had never seen that event before
    or it went from being an outlier to not.
    """

    BackfillStreamRow = namedtuple(
        "BackfillStreamRow",
        (
            "event_id",  # str
            "room_id",  # str
            "type",  # str
            "state_key",  # str, optional
            "redacts",  # str, optional
            "relates_to",  # str, optional
        ),
    )

    NAME = "backfill"
    ROW_TYPE = BackfillStreamRow

    def __init__(self, hs):
        self.store = hs.get_datastore()
        super().__init__(
            hs.get_instance_name(),
            self._current_token,
            self.store.get_all_new_backfill_event_rows,
        )

    def _current_token(self, instance_name: str) -> int:
        # The backfill stream over replication operates on *positive* numbers,
        # which means we need to negate it.
        return -self.store._backfill_id_gen.get_current_token_for_writer(instance_name)


class PresenceStream(Stream):
    PresenceStreamRow = namedtuple(
        "PresenceStreamRow",
        (
            "user_id",  # str
            "state",  # str
            "last_active_ts",  # int
            "last_federation_update_ts",  # int
            "last_user_sync_ts",  # int
            "status_msg",  # str
            "currently_active",  # bool
        ),
    )

    NAME = "presence"
    ROW_TYPE = PresenceStreamRow

    def __init__(self, hs):
        store = hs.get_datastore()

        if hs.config.worker_app is None:
            # on the master, query the presence handler
            presence_handler = hs.get_presence_handler()
            update_function = presence_handler.get_all_presence_updates
        else:
            # Query master process
            update_function = make_http_update_function(hs, self.NAME)

        super().__init__(
            hs.get_instance_name(),
            current_token_without_instance(store.get_current_presence_token),
            update_function,
        )


class TypingStream(Stream):
    TypingStreamRow = namedtuple(
        "TypingStreamRow", ("room_id", "user_ids")  # str  # list(str)
    )

    NAME = "typing"
    ROW_TYPE = TypingStreamRow

    def __init__(self, hs: "HomeServer"):
        writer_instance = hs.config.worker.writers.typing
        if writer_instance == hs.get_instance_name():
            # On the writer, query the typing handler
            typing_writer_handler = hs.get_typing_writer_handler()
            update_function = (
                typing_writer_handler.get_all_typing_updates
            )  # type: Callable[[str, int, int, int], Awaitable[Tuple[List[Tuple[int, Any]], int, bool]]]
            current_token_function = typing_writer_handler.get_current_token
        else:
            # Query the typing writer process
            update_function = make_http_update_function(hs, self.NAME)
            current_token_function = hs.get_typing_handler().get_current_token

        super().__init__(
            hs.get_instance_name(),
            current_token_without_instance(current_token_function),
            update_function,
        )


class ReceiptsStream(Stream):
    ReceiptsStreamRow = namedtuple(
        "ReceiptsStreamRow",
        (
            "room_id",  # str
            "receipt_type",  # str
            "user_id",  # str
            "event_id",  # str
            "data",  # dict
        ),
    )

    NAME = "receipts"
    ROW_TYPE = ReceiptsStreamRow

    def __init__(self, hs):
        store = hs.get_datastore()
        super().__init__(
            hs.get_instance_name(),
            current_token_without_instance(store.get_max_receipt_stream_id),
            store.get_all_updated_receipts,
        )


class PushRulesStream(Stream):
    """A user has changed their push rules"""

    PushRulesStreamRow = namedtuple("PushRulesStreamRow", ("user_id",))  # str

    NAME = "push_rules"
    ROW_TYPE = PushRulesStreamRow

    def __init__(self, hs):
        self.store = hs.get_datastore()

        super().__init__(
            hs.get_instance_name(),
            self._current_token,
            self.store.get_all_push_rule_updates,
        )

    def _current_token(self, instance_name: str) -> int:
        push_rules_token = self.store.get_max_push_rules_stream_id()
        return push_rules_token


class PushersStream(Stream):
    """A user has added/changed/removed a pusher"""

    PushersStreamRow = namedtuple(
        "PushersStreamRow",
        ("user_id", "app_id", "pushkey", "deleted"),  # str  # str  # str  # bool
    )

    NAME = "pushers"
    ROW_TYPE = PushersStreamRow

    def __init__(self, hs):
        store = hs.get_datastore()

        super().__init__(
            hs.get_instance_name(),
            current_token_without_instance(store.get_pushers_stream_token),
            store.get_all_updated_pushers_rows,
        )


class CachesStream(Stream):
    """A cache was invalidated on the master and no other stream would invalidate
    the cache on the workers
    """

    @attr.s(slots=True)
    class CachesStreamRow:
        """Stream to inform workers they should invalidate their cache.

        Attributes:
            cache_func: Name of the cached function.
            keys: The entry in the cache to invalidate. If None then will
                invalidate all.
            invalidation_ts: Timestamp of when the invalidation took place.
        """

        cache_func = attr.ib(type=str)
        keys = attr.ib(type=Optional[List[Any]])
        invalidation_ts = attr.ib(type=int)

    NAME = "caches"
    ROW_TYPE = CachesStreamRow

    def __init__(self, hs):
        store = hs.get_datastore()
        super().__init__(
            hs.get_instance_name(),
            store.get_cache_stream_token_for_writer,
            store.get_all_updated_caches,
        )


class PublicRoomsStream(Stream):
    """The public rooms list changed"""

    PublicRoomsStreamRow = namedtuple(
        "PublicRoomsStreamRow",
        (
            "room_id",  # str
            "visibility",  # str
            "appservice_id",  # str, optional
            "network_id",  # str, optional
        ),
    )

    NAME = "public_rooms"
    ROW_TYPE = PublicRoomsStreamRow

    def __init__(self, hs):
        store = hs.get_datastore()
        super().__init__(
            hs.get_instance_name(),
            current_token_without_instance(store.get_current_public_room_stream_id),
            store.get_all_new_public_rooms,
        )


class DeviceListsStream(Stream):
    """Either a user has updated their devices or a remote server needs to be
    told about a device update.
    """

    @attr.s(slots=True)
    class DeviceListsStreamRow:
        entity = attr.ib(type=str)

    NAME = "device_lists"
    ROW_TYPE = DeviceListsStreamRow

    def __init__(self, hs):
        store = hs.get_datastore()
        super().__init__(
            hs.get_instance_name(),
            current_token_without_instance(store.get_device_stream_token),
            store.get_all_device_list_changes_for_remotes,
        )


class ToDeviceStream(Stream):
    """New to_device messages for a client"""

    ToDeviceStreamRow = namedtuple("ToDeviceStreamRow", ("entity",))  # str

    NAME = "to_device"
    ROW_TYPE = ToDeviceStreamRow

    def __init__(self, hs):
        store = hs.get_datastore()
        super().__init__(
            hs.get_instance_name(),
            current_token_without_instance(store.get_to_device_stream_token),
            store.get_all_new_device_messages,
        )


class TagAccountDataStream(Stream):
    """Someone added/removed a tag for a room"""

    TagAccountDataStreamRow = namedtuple(
        "TagAccountDataStreamRow", ("user_id", "room_id", "data")  # str  # str  # dict
    )

    NAME = "tag_account_data"
    ROW_TYPE = TagAccountDataStreamRow

    def __init__(self, hs):
        store = hs.get_datastore()
        super().__init__(
            hs.get_instance_name(),
            current_token_without_instance(store.get_max_account_data_stream_id),
            store.get_all_updated_tags,
        )


class AccountDataStream(Stream):
    """Global or per room account data was changed"""

    AccountDataStreamRow = namedtuple(
        "AccountDataStreamRow",
        ("user_id", "room_id", "data_type"),  # str  # Optional[str]  # str
    )

    NAME = "account_data"
    ROW_TYPE = AccountDataStreamRow

    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastore()
        super().__init__(
            hs.get_instance_name(),
            current_token_without_instance(self.store.get_max_account_data_stream_id),
            self._update_function,
        )

    async def _update_function(
        self, instance_name: str, from_token: int, to_token: int, limit: int
    ) -> StreamUpdateResult:
        limited = False
        global_results = await self.store.get_updated_global_account_data(
            from_token, to_token, limit
        )

        # if the global results hit the limit, we'll need to limit the room results to
        # the same stream token.
        if len(global_results) >= limit:
            to_token = global_results[-1][0]
            limited = True

        room_results = await self.store.get_updated_room_account_data(
            from_token, to_token, limit
        )

        # likewise, if the room results hit the limit, limit the global results to
        # the same stream token.
        if len(room_results) >= limit:
            to_token = room_results[-1][0]
            limited = True

        # convert the global results to the right format, and limit them to the to_token
        # at the same time
        global_rows = (
            (stream_id, (user_id, None, account_data_type))
            for stream_id, user_id, account_data_type in global_results
            if stream_id <= to_token
        )

        # we know that the room_results are already limited to `to_token` so no need
        # for a check on `stream_id` here.
        room_rows = (
            (stream_id, (user_id, room_id, account_data_type))
            for stream_id, user_id, room_id, account_data_type in room_results
        )

        # We need to return a sorted list, so merge them together.
        #
        # Note: We order only by the stream ID to work around a bug where the
        # same stream ID could appear in both `global_rows` and `room_rows`,
        # leading to a comparison between the data tuples. The comparison could
        # fail due to attempting to compare the `room_id` which results in a
        # `TypeError` from comparing a `str` vs `None`.
        updates = list(heapq.merge(room_rows, global_rows, key=lambda row: row[0]))
        return updates, to_token, limited


class GroupServerStream(Stream):
    GroupsStreamRow = namedtuple(
        "GroupsStreamRow",
        ("group_id", "user_id", "type", "content"),  # str  # str  # str  # dict
    )

    NAME = "groups"
    ROW_TYPE = GroupsStreamRow

    def __init__(self, hs):
        store = hs.get_datastore()
        super().__init__(
            hs.get_instance_name(),
            current_token_without_instance(store.get_group_stream_token),
            store.get_all_groups_changes,
        )


class UserSignatureStream(Stream):
    """A user has signed their own device with their user-signing key"""

    UserSignatureStreamRow = namedtuple("UserSignatureStreamRow", ("user_id"))  # str

    NAME = "user_signature"
    ROW_TYPE = UserSignatureStreamRow

    def __init__(self, hs):
        store = hs.get_datastore()
        super().__init__(
            hs.get_instance_name(),
            current_token_without_instance(store.get_device_stream_token),
            store.get_all_user_signature_changes_for_remotes,
        )
