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
from synapse.types import get_domain_from_id

import logging


logger = logging.getLogger(__name__)


class ReadMarkerHandler(BaseHandler):
    def __init__(self, hs):
        super(ReadMarkerHandler, self).__init__(hs)

        self.server_name = hs.config.server_name
        self.store = hs.get_datastore()

    @defer.inlineCallbacks
    def received_client_read_marker(self, room_id, user_id, event_id):
        """NEEDS DOC
        """

        room_id = read_marker["room_id"]
        user_id = read_marker["user_id"]
        event_id = read_marker["event_id"]

        # Get ordering for existing read marker
        account_data = yield self.store.get_account_data_for_room(user_id, room_id)
        existing_read_marker = account_data["m.read_marker"]

        if existing_read_marker:
            # Get ordering for new read marker
            res = self.store._simple_select_one_txn(
                txn,
                table="events",
                retcols=["topological_ordering", "stream_ordering"],
                keyvalues={"event_id": event_id},
                allow_none=True
            )
            new_to = int(res["topological_ordering"]) if res else None
            new_so = int(res["stream_ordering"]) if res else None

            res = self.store._simple_select_one_txn(
                txn,
                table="events",
                retcols=["topological_ordering", "stream_ordering"],
                keyvalues={"event_id": existing_read_marker.content.marker},
                allow_none=True
            )
            existing_to = int(res["topological_ordering"]) if res else None
            existing_so = int(res["stream_ordering"]) if res else None

            if new_to > existing_to:
                return False
            elif new_to == existing_to and new_so >= existing_so:
                return False

        # Update account data
        content = {
            "marker": event_id
        }
        yield self.store.add_account_data_to_room(
            user_id, room_id, "m.read_marker", content
        )
