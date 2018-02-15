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

from twisted.internet import defer

from synapse.api.errors import SynapseError, MatrixCodeMessageException
from synapse.events import FrozenEvent
from synapse.events.snapshot import EventContext
from synapse.http.servlet import RestServlet, parse_json_object_from_request
from synapse.util.metrics import Measure
from synapse.types import Requester

import logging
import re

logger = logging.getLogger(__name__)


@defer.inlineCallbacks
def send_event_to_master(client, host, port, requester, event, context):
    """Send event to be handled on the master

    Args:
        client (SimpleHttpClient)
        host (str): host of master
        port (int): port on master listening for HTTP replication
        requester (Requester)
        event (FrozenEvent)
        context (EventContext)
    """
    uri = "http://%s:%s/_synapse/replication/send_event" % (host, port,)

    payload = {
        "event": event.get_pdu_json(),
        "internal_metadata": event.internal_metadata.get_dict(),
        "rejected_reason": event.rejected_reason,
        "context": context.serialize(event),
        "requester": requester.serialize(),
    }

    try:
        result = yield client.post_json_get_json(uri, payload)
    except MatrixCodeMessageException as e:
        # We convert to SynapseError as we know that it was a SynapseError
        # on the master process that we should send to the client. (And
        # importantly, not stack traces everywhere)
        raise SynapseError(e.code, e.msg, e.errcode)
    defer.returnValue(result)


class ReplicationSendEventRestServlet(RestServlet):
    """Handles events newly created on workers, including persisting and
    notifying.

    The API looks like:

        POST /_synapse/replication/send_event

        {
            "event": { .. serialized event .. },
            "internal_metadata": { .. serialized internal_metadata .. },
            "rejected_reason": ..,   // The event.rejected_reason field
            "context": { .. serialized event context .. },
            "requester": { .. serialized requester .. },
        }
    """
    PATTERNS = [re.compile("^/_synapse/replication/send_event$")]

    def __init__(self, hs):
        super(ReplicationSendEventRestServlet, self).__init__()

        self.event_creation_handler = hs.get_event_creation_handler()
        self.store = hs.get_datastore()
        self.clock = hs.get_clock()

    @defer.inlineCallbacks
    def on_POST(self, request):
        with Measure(self.clock, "repl_send_event_parse"):
            content = parse_json_object_from_request(request)

            event_dict = content["event"]
            internal_metadata = content["internal_metadata"]
            rejected_reason = content["rejected_reason"]
            event = FrozenEvent(event_dict, internal_metadata, rejected_reason)

            requester = Requester.deserialize(self.store, content["requester"])
            context = yield EventContext.deserialize(self.store, content["context"])

        if requester.user:
            request.authenticated_entity = requester.user.to_string()

        logger.info(
            "Got event to send with ID: %s into room: %s",
            event.event_id, event.room_id,
        )

        yield self.event_creation_handler.handle_new_client_event(
            requester, event, context,
        )

        defer.returnValue((200, {}))


def register_servlets(hs, http_server):
    ReplicationSendEventRestServlet(hs).register(http_server)
