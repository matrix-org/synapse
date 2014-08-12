# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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

from .pdu_codec import PduCodec

from synapse.api.errors import AuthError
from synapse.util.logutils import log_function

import logging


logger = logging.getLogger(__name__)


class FederationEventHandler(object):
    """ Responsible for:
        a) handling received Pdus before handing them on as Events to the rest
        of the home server (including auth and state conflict resoultion)
        b) converting events that were produced by local clients that may need
        to be sent to remote home servers.
    """

    def __init__(self, hs):
        self.store = hs.get_datastore()
        self.replication_layer = hs.get_replication_layer()
        self.state_handler = hs.get_state_handler()
        # self.auth_handler = gs.get_auth_handler()
        self.event_handler = hs.get_handlers().federation_handler
        self.server_name = hs.hostname

        self.lock_manager = hs.get_room_lock_manager()

        self.replication_layer.set_handler(self)

        self.pdu_codec = PduCodec(hs)

    @log_function
    @defer.inlineCallbacks
    def handle_new_event(self, event):
        """ Takes in an event from the client to server side, that has already
        been authed and handled by the state module, and sends it to any
        remote home servers that may be interested.

        Args:
            event

        Returns:
            Deferred: Resolved when it has successfully been queued for
            processing.
        """
        yield self._fill_out_prev_events(event)

        pdu = self.pdu_codec.pdu_from_event(event)

        if not hasattr(pdu, "destinations") or not pdu.destinations:
            pdu.destinations = []

        yield self.replication_layer.send_pdu(pdu)

    @log_function
    @defer.inlineCallbacks
    def backfill(self, room_id, limit):
        # TODO: Work out which destinations to ask for pagination
        # self.replication_layer.paginate(dest, room_id, limit)
        pass

    @log_function
    def get_state_for_room(self, destination, room_id):
        return self.replication_layer.get_state_for_context(
            destination, room_id
        )

    @log_function
    @defer.inlineCallbacks
    def on_receive_pdu(self, pdu):
        """ Called by the ReplicationLayer when we have a new pdu. We need to
        do auth checks and put it throught the StateHandler.
        """
        event = self.pdu_codec.event_from_pdu(pdu)

        try:
            with (yield self.lock_manager.lock(pdu.context)):
                if event.is_state:
                    is_new_state = yield self.state_handler.handle_new_state(
                        pdu
                    )
                    if not is_new_state:
                        return
                else:
                    is_new_state = False

            yield self.event_handler.on_receive(event, is_new_state)

        except AuthError:
            # TODO: Implement something in federation that allows us to
            # respond to PDU.
            raise

        return

    @defer.inlineCallbacks
    def _on_new_state(self, pdu, new_state_event):
        # TODO: Do any store stuff here. Notifiy C2S about this new
        # state.

        yield self.store.update_current_state(
            pdu_id=pdu.pdu_id,
            origin=pdu.origin,
            context=pdu.context,
            pdu_type=pdu.pdu_type,
            state_key=pdu.state_key
        )

        yield self.event_handler.on_receive(new_state_event)

    @defer.inlineCallbacks
    def _fill_out_prev_events(self, event):
        if hasattr(event, "prev_events"):
            return

        results = yield self.store.get_latest_pdus_in_context(
            event.room_id
        )

        es = [
            "%s@%s" % (p_id, origin) for p_id, origin, _ in results
        ]

        event.prev_events = [e for e in es if e != event.event_id]

        if results:
            event.depth = max([int(v) for _, _, v in results]) + 1
        else:
            event.depth = 0
