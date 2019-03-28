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


import itertools
import logging
from collections import namedtuple

from twisted.internet import defer

logger = logging.getLogger(__name__)


MAX_EVENTS_BEHIND = 10000

BackfillStreamRow = namedtuple("BackfillStreamRow", (
    "event_id",  # str
    "room_id",  # str
    "type",  # str
    "state_key",  # str, optional
    "redacts",  # str, optional
))
PresenceStreamRow = namedtuple("PresenceStreamRow", (
    "user_id",  # str
    "state",  # str
    "last_active_ts",  # int
    "last_federation_update_ts",  # int
    "last_user_sync_ts",  # int
    "status_msg",   # str
    "currently_active",  # bool
))
TypingStreamRow = namedtuple("TypingStreamRow", (
    "room_id",  # str
    "user_ids",  # list(str)
))
ReceiptsStreamRow = namedtuple("ReceiptsStreamRow", (
    "room_id",  # str
    "receipt_type",  # str
    "user_id",  # str
    "event_id",  # str
    "data",  # dict
))
PushRulesStreamRow = namedtuple("PushRulesStreamRow", (
    "user_id",  # str
))
PushersStreamRow = namedtuple("PushersStreamRow", (
    "user_id",  # str
    "app_id",  # str
    "pushkey",  # str
    "deleted",  # bool
))
CachesStreamRow = namedtuple("CachesStreamRow", (
    "cache_func",  # str
    "keys",  # list(str)
    "invalidation_ts",  # int
))
PublicRoomsStreamRow = namedtuple("PublicRoomsStreamRow", (
    "room_id",  # str
    "visibility",  # str
    "appservice_id",  # str, optional
    "network_id",  # str, optional
))
DeviceListsStreamRow = namedtuple("DeviceListsStreamRow", (
    "user_id",  # str
    "destination",  # str
))
ToDeviceStreamRow = namedtuple("ToDeviceStreamRow", (
    "entity",  # str
))
TagAccountDataStreamRow = namedtuple("TagAccountDataStreamRow", (
    "user_id",  # str
    "room_id",  # str
    "data",  # dict
))
AccountDataStreamRow = namedtuple("AccountDataStream", (
    "user_id",  # str
    "room_id",  # str
    "data_type",  # str
    "data",  # dict
))
GroupsStreamRow = namedtuple("GroupsStreamRow", (
    "group_id",  # str
    "user_id",  # str
    "type",  # str
    "content",  # dict
))


class Stream(object):
    """Base class for the streams.

    Provides a `get_updates()` function that returns new updates since the last
    time it was called up until the point `advance_current_token` was called.
    """
    NAME = None  # The name of the stream
    ROW_TYPE = None  # The type of the row. Used by the default impl of parse_row.
    _LIMITED = True  # Whether the update function takes a limit

    @classmethod
    def parse_row(cls, row):
        """Parse a row received over replication

        By default, assumes that the row data is an array object and passes its contents
        to the constructor of the ROW_TYPE for this stream.

        Args:
            row: row data from the incoming RDATA command, after json decoding

        Returns:
            ROW_TYPE object for this stream
        """
        return cls.ROW_TYPE(*row)

    def __init__(self, hs):
        # The token from which we last asked for updates
        self.last_token = self.current_token()

        # The token that we will get updates up to
        self.upto_token = self.current_token()

    def advance_current_token(self):
        """Updates `upto_token` to "now", which updates up until which point
        get_updates[_since] will fetch rows till.
        """
        self.upto_token = self.current_token()

    def discard_updates_and_advance(self):
        """Called when the stream should advance but the updates would be discarded,
        e.g. when there are no currently connected workers.
        """
        self.upto_token = self.current_token()
        self.last_token = self.upto_token

    @defer.inlineCallbacks
    def get_updates(self):
        """Gets all updates since the last time this function was called (or
        since the stream was constructed if it hadn't been called before),
        until the `upto_token`

        Returns:
            Deferred[Tuple[List[Tuple[int, Any]], int]:
                Resolves to a pair ``(updates, current_token)``, where ``updates`` is a
                list of ``(token, row)`` entries. ``row`` will be json-serialised and
                sent over the replication steam.
        """
        updates, current_token = yield self.get_updates_since(self.last_token)
        self.last_token = current_token

        defer.returnValue((updates, current_token))

    @defer.inlineCallbacks
    def get_updates_since(self, from_token):
        """Like get_updates except allows specifying from when we should
        stream updates

        Returns:
            Deferred[Tuple[List[Tuple[int, Any]], int]:
                Resolves to a pair ``(updates, current_token)``, where ``updates`` is a
                list of ``(token, row)`` entries. ``row`` will be json-serialised and
                sent over the replication steam.
        """
        if from_token in ("NOW", "now"):
            defer.returnValue(([], self.upto_token))

        current_token = self.upto_token

        from_token = int(from_token)

        if from_token == current_token:
            defer.returnValue(([], current_token))

        if self._LIMITED:
            rows = yield self.update_function(
                from_token, current_token,
                limit=MAX_EVENTS_BEHIND + 1,
            )

            # never turn more than MAX_EVENTS_BEHIND + 1 into updates.
            rows = itertools.islice(rows, MAX_EVENTS_BEHIND + 1)
        else:
            rows = yield self.update_function(
                from_token, current_token,
            )

        updates = [(row[0], row[1:]) for row in rows]

        # check we didn't get more rows than the limit.
        # doing it like this allows the update_function to be a generator.
        if self._LIMITED and len(updates) >= MAX_EVENTS_BEHIND:
            raise Exception("stream %s has fallen behind" % (self.NAME))

        defer.returnValue((updates, current_token))

    def current_token(self):
        """Gets the current token of the underlying streams. Should be provided
        by the sub classes

        Returns:
            int
        """
        raise NotImplementedError()

    def update_function(self, from_token, current_token, limit=None):
        """Get updates between from_token and to_token. If Stream._LIMITED is
        True then limit is provided, otherwise it's not.

        Returns:
            Deferred(list(tuple)): the first entry in the tuple is the token for
                that update, and the rest of the tuple gets used to construct
                a ``ROW_TYPE`` instance
        """
        raise NotImplementedError()


class BackfillStream(Stream):
    """We fetched some old events and either we had never seen that event before
    or it went from being an outlier to not.
    """
    NAME = "backfill"
    ROW_TYPE = BackfillStreamRow

    def __init__(self, hs):
        store = hs.get_datastore()
        self.current_token = store.get_current_backfill_token
        self.update_function = store.get_all_new_backfill_event_rows

        super(BackfillStream, self).__init__(hs)


class PresenceStream(Stream):
    NAME = "presence"
    _LIMITED = False
    ROW_TYPE = PresenceStreamRow

    def __init__(self, hs):
        store = hs.get_datastore()
        presence_handler = hs.get_presence_handler()

        self.current_token = store.get_current_presence_token
        self.update_function = presence_handler.get_all_presence_updates

        super(PresenceStream, self).__init__(hs)


class TypingStream(Stream):
    NAME = "typing"
    _LIMITED = False
    ROW_TYPE = TypingStreamRow

    def __init__(self, hs):
        typing_handler = hs.get_typing_handler()

        self.current_token = typing_handler.get_current_token
        self.update_function = typing_handler.get_all_typing_updates

        super(TypingStream, self).__init__(hs)


class ReceiptsStream(Stream):
    NAME = "receipts"
    ROW_TYPE = ReceiptsStreamRow

    def __init__(self, hs):
        store = hs.get_datastore()

        self.current_token = store.get_max_receipt_stream_id
        self.update_function = store.get_all_updated_receipts

        super(ReceiptsStream, self).__init__(hs)


class PushRulesStream(Stream):
    """A user has changed their push rules
    """
    NAME = "push_rules"
    ROW_TYPE = PushRulesStreamRow

    def __init__(self, hs):
        self.store = hs.get_datastore()
        super(PushRulesStream, self).__init__(hs)

    def current_token(self):
        push_rules_token, _ = self.store.get_push_rules_stream_token()
        return push_rules_token

    @defer.inlineCallbacks
    def update_function(self, from_token, to_token, limit):
        rows = yield self.store.get_all_push_rule_updates(from_token, to_token, limit)
        defer.returnValue([(row[0], row[2]) for row in rows])


class PushersStream(Stream):
    """A user has added/changed/removed a pusher
    """
    NAME = "pushers"
    ROW_TYPE = PushersStreamRow

    def __init__(self, hs):
        store = hs.get_datastore()

        self.current_token = store.get_pushers_stream_token
        self.update_function = store.get_all_updated_pushers_rows

        super(PushersStream, self).__init__(hs)


class CachesStream(Stream):
    """A cache was invalidated on the master and no other stream would invalidate
    the cache on the workers
    """
    NAME = "caches"
    ROW_TYPE = CachesStreamRow

    def __init__(self, hs):
        store = hs.get_datastore()

        self.current_token = store.get_cache_stream_token
        self.update_function = store.get_all_updated_caches

        super(CachesStream, self).__init__(hs)


class PublicRoomsStream(Stream):
    """The public rooms list changed
    """
    NAME = "public_rooms"
    ROW_TYPE = PublicRoomsStreamRow

    def __init__(self, hs):
        store = hs.get_datastore()

        self.current_token = store.get_current_public_room_stream_id
        self.update_function = store.get_all_new_public_rooms

        super(PublicRoomsStream, self).__init__(hs)


class DeviceListsStream(Stream):
    """Someone added/changed/removed a device
    """
    NAME = "device_lists"
    _LIMITED = False
    ROW_TYPE = DeviceListsStreamRow

    def __init__(self, hs):
        store = hs.get_datastore()

        self.current_token = store.get_device_stream_token
        self.update_function = store.get_all_device_list_changes_for_remotes

        super(DeviceListsStream, self).__init__(hs)


class ToDeviceStream(Stream):
    """New to_device messages for a client
    """
    NAME = "to_device"
    ROW_TYPE = ToDeviceStreamRow

    def __init__(self, hs):
        store = hs.get_datastore()

        self.current_token = store.get_to_device_stream_token
        self.update_function = store.get_all_new_device_messages

        super(ToDeviceStream, self).__init__(hs)


class TagAccountDataStream(Stream):
    """Someone added/removed a tag for a room
    """
    NAME = "tag_account_data"
    ROW_TYPE = TagAccountDataStreamRow

    def __init__(self, hs):
        store = hs.get_datastore()

        self.current_token = store.get_max_account_data_stream_id
        self.update_function = store.get_all_updated_tags

        super(TagAccountDataStream, self).__init__(hs)


class AccountDataStream(Stream):
    """Global or per room account data was changed
    """
    NAME = "account_data"
    ROW_TYPE = AccountDataStreamRow

    def __init__(self, hs):
        self.store = hs.get_datastore()

        self.current_token = self.store.get_max_account_data_stream_id

        super(AccountDataStream, self).__init__(hs)

    @defer.inlineCallbacks
    def update_function(self, from_token, to_token, limit):
        global_results, room_results = yield self.store.get_all_updated_account_data(
            from_token, from_token, to_token, limit
        )

        results = list(room_results)
        results.extend(
            (stream_id, user_id, None, account_data_type, content,)
            for stream_id, user_id, account_data_type, content in global_results
        )

        defer.returnValue(results)


class GroupServerStream(Stream):
    NAME = "groups"
    ROW_TYPE = GroupsStreamRow

    def __init__(self, hs):
        store = hs.get_datastore()

        self.current_token = store.get_group_stream_token
        self.update_function = store.get_all_groups_changes

        super(GroupServerStream, self).__init__(hs)
