# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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

from synapse.http.servlet import parse_integer, parse_string
from synapse.http.server import request_handler, finish_request

from twisted.web.resource import Resource
from twisted.web.server import NOT_DONE_YET
from twisted.internet import defer

import ujson as json

import collections
import logging

logger = logging.getLogger(__name__)

REPLICATION_PREFIX = "/_synapse/replication"

STREAM_NAMES = (
    ("events",),
    ("presence",),
    ("typing",),
    ("receipts",),
    ("user_account_data", "room_account_data", "tag_account_data",),
    ("backfill",),
    ("push_rules",),
    ("pushers",),
)


class ReplicationResource(Resource):
    """
    HTTP endpoint for extracting data from synapse.

    The streams of data returned by the endpoint are controlled by the
    parameters given to the API. To return a given stream pass a query
    parameter with a position in the stream to return data from or the
    special value "-1" to return data from the start of the stream.

    If there is no data for any of the supplied streams after the given
    position then the request will block until there is data for one
    of the streams. This allows clients to long-poll this API.

    The possible streams are:

    * "streams": A special stream returing the positions of other streams.
    * "events": The new events seen on the server.
    * "presence": Presence updates.
    * "typing": Typing updates.
    * "receipts": Receipt updates.
    * "user_account_data": Top-level per user account data.
    * "room_account_data: Per room per user account data.
    * "tag_account_data": Per room per user tags.
    * "backfill": Old events that have been backfilled from other servers.
    * "push_rules": Per user changes to push rules.
    * "pushers": Per user changes to their pushers.

    The API takes two additional query parameters:

    * "timeout": How long to wait before returning an empty response.
    * "limit": The maximum number of rows to return for the selected streams.

    The response is a JSON object with keys for each stream with updates. Under
    each key is a JSON object with:

    * "postion": The current position of the stream.
    * "field_names": The names of the fields in each row.
    * "rows": The updates as an array of arrays.

    There are a number of ways this API could be used:

    1) To replicate the contents of the backing database to another database.
    2) To be notified when the contents of a shared backing database changes.
    3) To "tail" the activity happening on a server for debugging.

    In the first case the client would track all of the streams and store it's
    own copy of the data.

    In the second case the client might theoretically just be able to follow
    the "streams" stream to track where the other streams are. However in
    practise it will probably need to get the contents of the streams in
    order to expire the any in-memory caches. Whether it gets the contents
    of the streams from this replication API or directly from the backing
    store is a matter of taste.

    In the third case the client would use the "streams" stream to find what
    streams are available and their current positions. Then it can start
    long-polling this replication API for new data on those streams.
    """

    isLeaf = True

    def __init__(self, hs):
        Resource.__init__(self)  # Resource is old-style, so no super()

        self.version_string = hs.version_string
        self.store = hs.get_datastore()
        self.sources = hs.get_event_sources()
        self.presence_handler = hs.get_handlers().presence_handler
        self.typing_handler = hs.get_handlers().typing_notification_handler
        self.notifier = hs.notifier

    def render_GET(self, request):
        self._async_render_GET(request)
        return NOT_DONE_YET

    @defer.inlineCallbacks
    def current_replication_token(self):
        stream_token = yield self.sources.get_current_token()
        backfill_token = yield self.store.get_current_backfill_token()
        push_rules_token, room_stream_token = self.store.get_push_rules_stream_token()
        pushers_token = self.store.get_pushers_stream_token()

        defer.returnValue(_ReplicationToken(
            room_stream_token,
            int(stream_token.presence_key),
            int(stream_token.typing_key),
            int(stream_token.receipt_key),
            int(stream_token.account_data_key),
            backfill_token,
            push_rules_token,
            pushers_token,
        ))

    @request_handler
    @defer.inlineCallbacks
    def _async_render_GET(self, request):
        limit = parse_integer(request, "limit", 100)
        timeout = parse_integer(request, "timeout", 10 * 1000)

        request.setHeader(b"Content-Type", b"application/json")
        writer = _Writer(request)

        @defer.inlineCallbacks
        def replicate():
            current_token = yield self.current_replication_token()
            logger.info("Replicating up to %r", current_token)

            yield self.account_data(writer, current_token, limit)
            yield self.events(writer, current_token, limit)
            yield self.presence(writer, current_token)  # TODO: implement limit
            yield self.typing(writer, current_token)  # TODO: implement limit
            yield self.receipts(writer, current_token, limit)
            yield self.push_rules(writer, current_token, limit)
            yield self.pushers(writer, current_token, limit)
            self.streams(writer, current_token)

            logger.info("Replicated %d rows", writer.total)
            defer.returnValue(writer.total)

        yield self.notifier.wait_for_replication(replicate, timeout)

        writer.finish()

    def streams(self, writer, current_token):
        request_token = parse_string(writer.request, "streams")

        streams = []

        if request_token is not None:
            if request_token == "-1":
                for names, position in zip(STREAM_NAMES, current_token):
                    streams.extend((name, position) for name in names)
            else:
                items = zip(
                    STREAM_NAMES,
                    current_token,
                    _ReplicationToken(request_token)
                )
                for names, current_id, last_id in items:
                    if last_id < current_id:
                        streams.extend((name, current_id) for name in names)

            if streams:
                writer.write_header_and_rows(
                    "streams", streams, ("name", "position"),
                    position=str(current_token)
                )

    @defer.inlineCallbacks
    def events(self, writer, current_token, limit):
        request_events = parse_integer(writer.request, "events")
        request_backfill = parse_integer(writer.request, "backfill")

        if request_events is not None or request_backfill is not None:
            if request_events is None:
                request_events = current_token.events
            if request_backfill is None:
                request_backfill = current_token.backfill
            events_rows, backfill_rows = yield self.store.get_all_new_events(
                request_backfill, request_events,
                current_token.backfill, current_token.events,
                limit
            )
            writer.write_header_and_rows(
                "events", events_rows, ("position", "internal", "json")
            )
            writer.write_header_and_rows(
                "backfill", backfill_rows, ("position", "internal", "json")
            )

    @defer.inlineCallbacks
    def presence(self, writer, current_token):
        current_position = current_token.presence

        request_presence = parse_integer(writer.request, "presence")

        if request_presence is not None:
            presence_rows = yield self.presence_handler.get_all_presence_updates(
                request_presence, current_position
            )
            writer.write_header_and_rows("presence", presence_rows, (
                "position", "user_id", "state", "last_active_ts",
                "last_federation_update_ts", "last_user_sync_ts",
                "status_msg", "currently_active",
            ))

    @defer.inlineCallbacks
    def typing(self, writer, current_token):
        current_position = current_token.presence

        request_typing = parse_integer(writer.request, "typing")

        if request_typing is not None:
            typing_rows = yield self.typing_handler.get_all_typing_updates(
                request_typing, current_position
            )
            writer.write_header_and_rows("typing", typing_rows, (
                "position", "room_id", "typing"
            ))

    @defer.inlineCallbacks
    def receipts(self, writer, current_token, limit):
        current_position = current_token.receipts

        request_receipts = parse_integer(writer.request, "receipts")

        if request_receipts is not None:
            receipts_rows = yield self.store.get_all_updated_receipts(
                request_receipts, current_position, limit
            )
            writer.write_header_and_rows("receipts", receipts_rows, (
                "position", "room_id", "receipt_type", "user_id", "event_id", "data"
            ))

    @defer.inlineCallbacks
    def account_data(self, writer, current_token, limit):
        current_position = current_token.account_data

        user_account_data = parse_integer(writer.request, "user_account_data")
        room_account_data = parse_integer(writer.request, "room_account_data")
        tag_account_data = parse_integer(writer.request, "tag_account_data")

        if user_account_data is not None or room_account_data is not None:
            if user_account_data is None:
                user_account_data = current_position
            if room_account_data is None:
                room_account_data = current_position
            user_rows, room_rows = yield self.store.get_all_updated_account_data(
                user_account_data, room_account_data, current_position, limit
            )
            writer.write_header_and_rows("user_account_data", user_rows, (
                "position", "user_id", "type", "content"
            ))
            writer.write_header_and_rows("room_account_data", room_rows, (
                "position", "user_id", "room_id", "type", "content"
            ))

        if tag_account_data is not None:
            tag_rows = yield self.store.get_all_updated_tags(
                tag_account_data, current_position, limit
            )
            writer.write_header_and_rows("tag_account_data", tag_rows, (
                "position", "user_id", "room_id", "tags"
            ))

    @defer.inlineCallbacks
    def push_rules(self, writer, current_token, limit):
        current_position = current_token.push_rules

        push_rules = parse_integer(writer.request, "push_rules")

        if push_rules is not None:
            rows = yield self.store.get_all_push_rule_updates(
                push_rules, current_position, limit
            )
            writer.write_header_and_rows("push_rules", rows, (
                "position", "event_stream_ordering", "user_id", "rule_id", "op",
                "priority_class", "priority", "conditions", "actions"
            ))

    @defer.inlineCallbacks
    def pushers(self, writer, current_token, limit):
        current_position = current_token.pushers

        pushers = parse_integer(writer.request, "pushers")
        if pushers is not None:
            updated, deleted = yield self.store.get_all_updated_pushers(
                pushers, current_position, limit
            )
            writer.write_header_and_rows("pushers", updated, (
                "position", "user_id", "access_token", "profile_tag", "kind",
                "app_id", "app_display_name", "device_display_name", "pushkey",
                "ts", "lang", "data"
            ))
            writer.write_header_and_rows("deleted", deleted, (
                "position", "user_id", "app_id", "pushkey"
            ))


class _Writer(object):
    """Writes the streams as a JSON object as the response to the request"""
    def __init__(self, request):
        self.streams = {}
        self.request = request
        self.total = 0

    def write_header_and_rows(self, name, rows, fields, position=None):
        if not rows:
            return

        if position is None:
            position = rows[-1][0]

        self.streams[name] = {
            "position": str(position),
            "field_names": fields,
            "rows": rows,
        }

        self.total += len(rows)

    def finish(self):
        self.request.write(json.dumps(self.streams, ensure_ascii=False))
        finish_request(self.request)


class _ReplicationToken(collections.namedtuple("_ReplicationToken", (
    "events", "presence", "typing", "receipts", "account_data", "backfill",
    "push_rules", "pushers"
))):
    __slots__ = []

    def __new__(cls, *args):
        if len(args) == 1:
            streams = [int(value) for value in args[0].split("_")]
            if len(streams) < len(cls._fields):
                streams.extend([0] * (len(cls._fields) - len(streams)))
            return cls(*streams)
        else:
            return super(_ReplicationToken, cls).__new__(cls, *args)

    def __str__(self):
        return "_".join(str(value) for value in self)
