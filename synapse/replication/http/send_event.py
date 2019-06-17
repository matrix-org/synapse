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
from synapse.types import Requester, UserID
from synapse.util.metrics import Measure

logger = logging.getLogger(__name__)


class ReplicationSendEventRestServlet(ReplicationEndpoint):
    """Handles events newly created on workers, including persisting and
    notifying.

    The API looks like:

        POST /_synapse/replication/send_event/:event_id/:txn_id

        {
            "event": { .. serialized event .. },
            "internal_metadata": { .. serialized internal_metadata .. },
            "rejected_reason": ..,   // The event.rejected_reason field
            "context": { .. serialized event context .. },
            "requester": { .. serialized requester .. },
            "ratelimit": true,
            "extra_users": [],
        }
    """

    NAME = "send_event"
    PATH_ARGS = ("event_id",)

    def __init__(self, hs):
        super(ReplicationSendEventRestServlet, self).__init__(hs)

        self.event_creation_handler = hs.get_event_creation_handler()
        self.store = hs.get_datastore()
        self.clock = hs.get_clock()

    @staticmethod
    @defer.inlineCallbacks
    def _serialize_payload(
        event_id, store, event, context, requester, ratelimit, extra_users
    ):
        """
        Args:
            event_id (str)
            store (DataStore)
            requester (Requester)
            event (FrozenEvent)
            context (EventContext)
            ratelimit (bool)
            extra_users (list(UserID)): Any extra users to notify about event
        """

        serialized_context = yield context.serialize(event, store)

        payload = {
            "event": event.get_pdu_json(),
            "event_format_version": event.format_version,
            "internal_metadata": event.internal_metadata.get_dict(),
            "rejected_reason": event.rejected_reason,
            "context": serialized_context,
            "requester": requester.serialize(),
            "ratelimit": ratelimit,
            "extra_users": [u.to_string() for u in extra_users],
        }

        defer.returnValue(payload)

    @defer.inlineCallbacks
    def _handle_request(self, request, event_id):
        with Measure(self.clock, "repl_send_event_parse"):
            content = parse_json_object_from_request(request)

            event_dict = content["event"]
            format_ver = content["event_format_version"]
            internal_metadata = content["internal_metadata"]
            rejected_reason = content["rejected_reason"]

            EventType = event_type_from_format_version(format_ver)
            event = EventType(event_dict, internal_metadata, rejected_reason)

            requester = Requester.deserialize(self.store, content["requester"])
            context = yield EventContext.deserialize(self.store, content["context"])

            ratelimit = content["ratelimit"]
            extra_users = [UserID.from_string(u) for u in content["extra_users"]]

        if requester.user:
            request.authenticated_entity = requester.user.to_string()

        logger.info(
            "Got event to send with ID: %s into room: %s", event.event_id, event.room_id
        )

        yield self.event_creation_handler.persist_and_notify_client_event(
            requester, event, context, ratelimit=ratelimit, extra_users=extra_users
        )

        defer.returnValue((200, {}))


def register_servlets(hs, http_server):
    ReplicationSendEventRestServlet(hs).register(http_server)
