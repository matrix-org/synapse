# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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

from ._base import BaseHandler

from twisted.internet import defer

from synapse.util.logcontext import PreserveLoggingContext
from synapse.util.async import Linearizer
from synapse.types import get_domain_from_id
from synapse.api.errors import SynapseError

import logging
logger = logging.getLogger(__name__)

class ReadMarkerHandler(BaseHandler):
    def __init__(self, hs):
        super(ReadMarkerHandler, self).__init__(hs)
        self.server_name = hs.config.server_name
        self.store = hs.get_datastore()
        self.read_marker_linearizer = Linearizer(name="read_marker")
        self.notifier = hs.get_notifier()

    @defer.inlineCallbacks
    def received_client_read_marker(self, room_id, user_id, event_id):
        """Updates the read marker for a given user in a given room if the event ID given
        is ahead in the stream relative to the current read marker.

        This uses a notifier to indicate that account data should be sent down /sync if
        the read marker has changed.
        """

        # Get ordering for existing read marker
        with (yield self.read_marker_linearizer.queue(room_id + "_" + user_id)):
            account_data = yield self.store.get_account_data_for_room(user_id, room_id)
            existing_read_marker = account_data["m.read_marker"]

            should_update = True

            res = yield self.store._simple_select_one(
                table="events",
                retcols=["topological_ordering", "stream_ordering"],
                keyvalues={"event_id": event_id},
                allow_none=True
            )

            if not res:
                raise SynapseError(404, 'Event does not exist')

            if existing_read_marker:
                new_to = int(res["topological_ordering"])
                new_so = int(res["stream_ordering"])

                # Get ordering for existing read marker
                res = yield self.store._simple_select_one(
                    table="events",
                    retcols=["topological_ordering", "stream_ordering"],
                    keyvalues={"event_id": existing_read_marker['marker']},
                    allow_none=True
                )
                existing_to = int(res["topological_ordering"]) if res else None
                existing_so = int(res["stream_ordering"]) if res else None

                # Prevent updating if the existing marker is ahead in the stream
                if existing_to > new_to:
                    should_update = False
                elif existing_to == new_to and existing_so >= new_so:
                    should_update = False

            if should_update:
                content = {
                    "marker": event_id
                }
                max_id = yield self.store.add_account_data_to_room(
                    user_id, room_id, "m.read_marker", content
                )
                self.notifier.on_new_event(
                    "account_data_key", max_id, users=[user_id], rooms=[room_id]
                )
