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
    def _filter_events_for_client(self, user_id, events):
        event_id_to_state = yield self.store.get_state_for_events(
            frozenset(e.event_id for e in events),
            types=(
                (EventTypes.RoomHistoryVisibility, ""),
                (EventTypes.Member, user_id),
            )
        )

        def allowed(event, state):
            if event.type == EventTypes.RoomHistoryVisibility:
                return True

            membership_ev = state.get((EventTypes.Member, user_id), None)
            if membership_ev:
                membership = membership_ev.membership
            else:
                membership = Membership.LEAVE

            if membership == Membership.JOIN:
                return True

            history = state.get((EventTypes.RoomHistoryVisibility, ''), None)
            if history:
                visibility = history.content.get("history_visibility", "shared")
            else:
                visibility = "shared"

            if visibility == "public":
                return True
            elif visibility == "shared":
                return True
            elif visibility == "joined":
                return membership == Membership.JOIN
            elif visibility == "invited":
                return membership == Membership.INVITE

            return True

        defer.returnValue([
            event
            for event in events
            if allowed(event, event_id_to_state[event.event_id])
        ])

    @defer.inlineCallbacks
    def search(self, user, content):
        try:
            search_term = content["search_categories"]["room_events"]["search_term"]
            keys = content["search_categories"]["room_events"]["keys"]
        except KeyError:
            raise SynapseError(400, "Invalid search query")

        rooms = yield self.store.get_rooms_for_user_where_membership_is(
            user.to_string(),
            membership_list=[Membership.JOIN],
            # membership_list=[Membership.JOIN, Membership.LEAVE, Membership.Ban],
        )
        room_ids = set(r.room_id for r in rooms)

        rank_map, event_map = yield self.store.search_msgs(room_ids, search_term, keys)

        allowed_events = yield self._filter_events_for_client(
            user.to_string(), event_map.values()
        )

        time_now = self.clock.time_msec()

        results = {
            e.event_id: {
                "rank": rank_map[e.event_id],
                "result": serialize_event(e, time_now)
            }
            for e in allowed_events
        }

        logger.info("returning: %r", results)

        defer.returnValue({
            "search_categories": {
                "room_events": {
                    "results": results,
                    "count": len(results)
                }
            }
        })
