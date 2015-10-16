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

from twisted.internet import defer

from ._base import BaseHandler

from synapse.api.constants import (
    EventTypes, Membership,
)
from synapse.api.errors import SynapseError
from synapse.events.utils import serialize_event

import logging


logger = logging.getLogger(__name__)


class SearchHandler(BaseHandler):

    def __init__(self, hs):
        super(SearchHandler, self).__init__(hs)

    @defer.inlineCallbacks
    def search(self, user, content):
        """Performs a full text search for a user.

        Args:
            user (UserID)
            content (dict): Search parameters

        Returns:
            dict to be returned to the client with results of search
        """

        try:
            search_term = content["search_categories"]["room_events"]["search_term"]
            keys = content["search_categories"]["room_events"].get("keys", [
                "content.body", "content.name", "content.topic",
            ])
        except KeyError:
            raise SynapseError(400, "Invalid search query")

        # TODO: Search through left rooms too
        rooms = yield self.store.get_rooms_for_user_where_membership_is(
            user.to_string(),
            membership_list=[Membership.JOIN],
            # membership_list=[Membership.JOIN, Membership.LEAVE, Membership.Ban],
        )
        room_ids = set(r.room_id for r in rooms)

        # TODO: Apply room filter to rooms list

        rank_map, event_map = yield self.store.search_msgs(room_ids, search_term, keys)

        allowed_events = yield self._filter_events_for_client(
            user.to_string(), event_map.values()
        )

        # TODO: Filter allowed_events
        # TODO: Add a limit

        time_now = self.clock.time_msec()

        results = {
            e.event_id: {
                "rank": rank_map[e.event_id],
                "result": serialize_event(e, time_now)
            }
            for e in allowed_events
        }

        logger.info("Found %d results", len(results))

        defer.returnValue({
            "search_categories": {
                "room_events": {
                    "results": results,
                    "count": len(results)
                }
            }
        })
