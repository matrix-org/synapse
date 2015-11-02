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

from synapse.api.constants import Membership
from synapse.api.filtering import Filter
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
            filter_dict = content["search_categories"]["room_events"].get("filter", {})
            event_context = content["search_categories"]["room_events"].get(
                "event_context", None
            )

            if event_context is not None:
                before_limit = int(event_context.get(
                    "before_limit", 5
                ))
                after_limit = int(event_context.get(
                    "after_limit", 5
                ))
        except KeyError:
            raise SynapseError(400, "Invalid search query")

        search_filter = Filter(filter_dict)

        # TODO: Search through left rooms too
        rooms = yield self.store.get_rooms_for_user_where_membership_is(
            user.to_string(),
            membership_list=[Membership.JOIN],
            # membership_list=[Membership.JOIN, Membership.LEAVE, Membership.Ban],
        )
        room_ids = set(r.room_id for r in rooms)

        room_ids = search_filter.filter_rooms(room_ids)

        rank_map, event_map, _ = yield self.store.search_msgs(
            room_ids, search_term, keys
        )

        filtered_events = search_filter.filter(event_map.values())

        allowed_events = yield self._filter_events_for_client(
            user.to_string(), filtered_events
        )

        allowed_events.sort(key=lambda e: -rank_map[e.event_id])
        allowed_events = allowed_events[:search_filter.limit()]

        if event_context is not None:
            now_token = yield self.hs.get_event_sources().get_current_token()

            contexts = {}
            for event in allowed_events:
                res = yield self.store.get_events_around(
                    event.room_id, event.event_id, before_limit, after_limit
                )

                res["events_before"] = yield self._filter_events_for_client(
                    user.to_string(), res["events_before"]
                )

                res["events_after"] = yield self._filter_events_for_client(
                    user.to_string(), res["events_after"]
                )

                res["start"] = now_token.copy_and_replace(
                    "room_key", res["start"]
                ).to_string()

                res["end"] = now_token.copy_and_replace(
                    "room_key", res["end"]
                ).to_string()

                contexts[event.event_id] = res
        else:
            contexts = {}

        # TODO: Add a limit

        time_now = self.clock.time_msec()

        for context in contexts.values():
            context["events_before"] = [
                serialize_event(e, time_now)
                for e in context["events_before"]
            ]
            context["events_after"] = [
                serialize_event(e, time_now)
                for e in context["events_after"]
            ]

        results = {
            e.event_id: {
                "rank": rank_map[e.event_id],
                "result": serialize_event(e, time_now),
                "context": contexts.get(e.event_id, {}),
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
