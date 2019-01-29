# -*- coding: utf-8 -*-
# Copyright 2018 New Vector Ltd
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

from synapse.events import event_type_from_format_version
from synapse.events.snapshot import EventContext
from synapse.http.servlet import parse_json_object_from_request
from synapse.replication.http._base import ReplicationEndpoint
from synapse.util.metrics import Measure

logger = logging.getLogger(__name__)


class ReplicationFederationSendEventsRestServlet(ReplicationEndpoint):
    """Handles events newly received from federation, including persisting and
    notifying.

    The API looks like:

        POST /_synapse/replication/fed_send_events/:txn_id

        {
            "events": [{
                "event": { .. serialized event .. },
                "internal_metadata": { .. serialized internal_metadata .. },
                "rejected_reason": ..,   // The event.rejected_reason field
                "context": { .. serialized event context .. },
            }],
            "backfilled": false
    """

    NAME = "fed_send_events"
    PATH_ARGS = ()

    def __init__(self, hs):
        super(ReplicationFederationSendEventsRestServlet, self).__init__(hs)

        self.store = hs.get_datastore()
        self.clock = hs.get_clock()
        self.federation_handler = hs.get_handlers().federation_handler

    @staticmethod
    @defer.inlineCallbacks
    def _serialize_payload(store, event_and_contexts, backfilled):
        """
        Args:
            store
            event_and_contexts (list[tuple[FrozenEvent, EventContext]])
            backfilled (bool): Whether or not the events are the result of
                backfilling
        """
        event_payloads = []
        for event, context in event_and_contexts:
            serialized_context = yield context.serialize(event, store)

            event_payloads.append({
                "event": event.get_pdu_json(),
                "event_format_version": event.format_version,
                "internal_metadata": event.internal_metadata.get_dict(),
                "rejected_reason": event.rejected_reason,
                "context": serialized_context,
            })

        payload = {
            "events": event_payloads,
            "backfilled": backfilled,
        }

        defer.returnValue(payload)

    @defer.inlineCallbacks
    def _handle_request(self, request):
        with Measure(self.clock, "repl_fed_send_events_parse"):
            content = parse_json_object_from_request(request)

            backfilled = content["backfilled"]

            event_payloads = content["events"]

            event_and_contexts = []
            for event_payload in event_payloads:
                event_dict = event_payload["event"]
                format_ver = event_payload["event_format_version"]
                internal_metadata = event_payload["internal_metadata"]
                rejected_reason = event_payload["rejected_reason"]

                EventType = event_type_from_format_version(format_ver)
                event = EventType(event_dict, internal_metadata, rejected_reason)

                context = yield EventContext.deserialize(
                    self.store, event_payload["context"],
                )

                event_and_contexts.append((event, context))

        logger.info(
            "Got %d events from federation",
            len(event_and_contexts),
        )

        yield self.federation_handler.persist_events_and_notify(
            event_and_contexts, backfilled,
        )

        defer.returnValue((200, {}))


class ReplicationFederationSendEduRestServlet(ReplicationEndpoint):
    """Handles EDUs newly received from federation, including persisting and
    notifying.

    Request format:

        POST /_synapse/replication/fed_send_edu/:edu_type/:txn_id

        {
            "origin": ...,
            "content: { ... }
        }
    """

    NAME = "fed_send_edu"
    PATH_ARGS = ("edu_type",)

    def __init__(self, hs):
        super(ReplicationFederationSendEduRestServlet, self).__init__(hs)

        self.store = hs.get_datastore()
        self.clock = hs.get_clock()
        self.registry = hs.get_federation_registry()

    @staticmethod
    def _serialize_payload(edu_type, origin, content):
        return {
            "origin": origin,
            "content": content,
        }

    @defer.inlineCallbacks
    def _handle_request(self, request, edu_type):
        with Measure(self.clock, "repl_fed_send_edu_parse"):
            content = parse_json_object_from_request(request)

            origin = content["origin"]
            edu_content = content["content"]

        logger.info(
            "Got %r edu from %s",
            edu_type, origin,
        )

        result = yield self.registry.on_edu(edu_type, origin, edu_content)

        defer.returnValue((200, result))


class ReplicationGetQueryRestServlet(ReplicationEndpoint):
    """Handle responding to queries from federation.

    Request format:

        POST /_synapse/replication/fed_query/:query_type

        {
            "args": { ... }
        }
    """

    NAME = "fed_query"
    PATH_ARGS = ("query_type",)

    # This is a query, so let's not bother caching
    CACHE = False

    def __init__(self, hs):
        super(ReplicationGetQueryRestServlet, self).__init__(hs)

        self.store = hs.get_datastore()
        self.clock = hs.get_clock()
        self.registry = hs.get_federation_registry()

    @staticmethod
    def _serialize_payload(query_type, args):
        """
        Args:
            query_type (str)
            args (dict): The arguments received for the given query type
        """
        return {
            "args": args,
        }

    @defer.inlineCallbacks
    def _handle_request(self, request, query_type):
        with Measure(self.clock, "repl_fed_query_parse"):
            content = parse_json_object_from_request(request)

            args = content["args"]

        logger.info(
            "Got %r query",
            query_type,
        )

        result = yield self.registry.on_query(query_type, args)

        defer.returnValue((200, result))


class ReplicationCleanRoomRestServlet(ReplicationEndpoint):
    """Called to clean up any data in DB for a given room, ready for the
    server to join the room.

    Request format:

        POST /_synapse/replication/fed_query/:fed_cleanup_room/:txn_id

        {}
    """

    NAME = "fed_cleanup_room"
    PATH_ARGS = ("room_id",)

    def __init__(self, hs):
        super(ReplicationCleanRoomRestServlet, self).__init__(hs)

        self.store = hs.get_datastore()

    @staticmethod
    def _serialize_payload(room_id, args):
        """
        Args:
            room_id (str)
        """
        return {}

    @defer.inlineCallbacks
    def _handle_request(self, request, room_id):
        yield self.store.clean_room_for_join(room_id)

        defer.returnValue((200, {}))


def register_servlets(hs, http_server):
    ReplicationFederationSendEventsRestServlet(hs).register(http_server)
    ReplicationFederationSendEduRestServlet(hs).register(http_server)
    ReplicationGetQueryRestServlet(hs).register(http_server)
    ReplicationCleanRoomRestServlet(hs).register(http_server)
