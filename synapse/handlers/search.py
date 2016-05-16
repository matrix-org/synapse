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

from twisted.internet import defer

from ._base import BaseHandler

from synapse.api.constants import Membership, EventTypes
from synapse.api.filtering import Filter
from synapse.api.errors import SynapseError
from synapse.events.utils import serialize_event
from synapse.visibility import filter_events_for_client

from unpaddedbase64 import decode_base64, encode_base64

import itertools
import logging


logger = logging.getLogger(__name__)


class SearchHandler(BaseHandler):

    def __init__(self, hs):
        super(SearchHandler, self).__init__(hs)

    @defer.inlineCallbacks
    def search(self, user, content, batch=None):
        """Performs a full text search for a user.

        Args:
            user (UserID)
            content (dict): Search parameters
            batch (str): The next_batch parameter. Used for pagination.

        Returns:
            dict to be returned to the client with results of search
        """

        batch_group = None
        batch_group_key = None
        batch_token = None
        if batch:
            try:
                b = decode_base64(batch)
                batch_group, batch_group_key, batch_token = b.split("\n")

                assert batch_group is not None
                assert batch_group_key is not None
                assert batch_token is not None
            except:
                raise SynapseError(400, "Invalid batch")

        try:
            room_cat = content["search_categories"]["room_events"]

            # The actual thing to query in FTS
            search_term = room_cat["search_term"]

            # Which "keys" to search over in FTS query
            keys = room_cat.get("keys", [
                "content.body", "content.name", "content.topic",
            ])

            # Filter to apply to results
            filter_dict = room_cat.get("filter", {})

            # What to order results by (impacts whether pagination can be doen)
            order_by = room_cat.get("order_by", "rank")

            # Return the current state of the rooms?
            include_state = room_cat.get("include_state", False)

            # Include context around each event?
            event_context = room_cat.get(
                "event_context", None
            )

            # Group results together? May allow clients to paginate within a
            # group
            group_by = room_cat.get("groupings", {}).get("group_by", {})
            group_keys = [g["key"] for g in group_by]

            if event_context is not None:
                before_limit = int(event_context.get(
                    "before_limit", 5
                ))
                after_limit = int(event_context.get(
                    "after_limit", 5
                ))

                # Return the historic display name and avatar for the senders
                # of the events?
                include_profile = bool(event_context.get("include_profile", False))
        except KeyError:
            raise SynapseError(400, "Invalid search query")

        if order_by not in ("rank", "recent"):
            raise SynapseError(400, "Invalid order by: %r" % (order_by,))

        if set(group_keys) - {"room_id", "sender"}:
            raise SynapseError(
                400,
                "Invalid group by keys: %r" % (set(group_keys) - {"room_id", "sender"},)
            )

        search_filter = Filter(filter_dict)

        # TODO: Search through left rooms too
        rooms = yield self.store.get_rooms_for_user_where_membership_is(
            user.to_string(),
            membership_list=[Membership.JOIN],
            # membership_list=[Membership.JOIN, Membership.LEAVE, Membership.Ban],
        )
        room_ids = set(r.room_id for r in rooms)

        room_ids = search_filter.filter_rooms(room_ids)

        if batch_group == "room_id":
            room_ids.intersection_update({batch_group_key})

        if not room_ids:
            defer.returnValue({
                "search_categories": {
                    "room_events": {
                        "results": [],
                        "count": 0,
                        "highlights": [],
                    }
                }
            })

        rank_map = {}  # event_id -> rank of event
        allowed_events = []
        room_groups = {}  # Holds result of grouping by room, if applicable
        sender_group = {}  # Holds result of grouping by sender, if applicable

        # Holds the next_batch for the entire result set if one of those exists
        global_next_batch = None

        highlights = set()

        count = None

        if order_by == "rank":
            search_result = yield self.store.search_msgs(
                room_ids, search_term, keys
            )

            count = search_result["count"]

            if search_result["highlights"]:
                highlights.update(search_result["highlights"])

            results = search_result["results"]

            results_map = {r["event"].event_id: r for r in results}

            rank_map.update({r["event"].event_id: r["rank"] for r in results})

            filtered_events = search_filter.filter([r["event"] for r in results])

            events = yield filter_events_for_client(
                self.store, user.to_string(), filtered_events
            )

            events.sort(key=lambda e: -rank_map[e.event_id])
            allowed_events = events[:search_filter.limit()]

            for e in allowed_events:
                rm = room_groups.setdefault(e.room_id, {
                    "results": [],
                    "order": rank_map[e.event_id],
                })
                rm["results"].append(e.event_id)

                s = sender_group.setdefault(e.sender, {
                    "results": [],
                    "order": rank_map[e.event_id],
                })
                s["results"].append(e.event_id)

        elif order_by == "recent":
            room_events = []
            i = 0

            pagination_token = batch_token

            # We keep looping and we keep filtering until we reach the limit
            # or we run out of things.
            # But only go around 5 times since otherwise synapse will be sad.
            while len(room_events) < search_filter.limit() and i < 5:
                i += 1
                search_result = yield self.store.search_rooms(
                    room_ids, search_term, keys, search_filter.limit() * 2,
                    pagination_token=pagination_token,
                )

                if search_result["highlights"]:
                    highlights.update(search_result["highlights"])

                count = search_result["count"]

                results = search_result["results"]

                results_map = {r["event"].event_id: r for r in results}

                rank_map.update({r["event"].event_id: r["rank"] for r in results})

                filtered_events = search_filter.filter([
                    r["event"] for r in results
                ])

                events = yield filter_events_for_client(
                    self.store, user.to_string(), filtered_events
                )

                room_events.extend(events)
                room_events = room_events[:search_filter.limit()]

                if len(results) < search_filter.limit() * 2:
                    pagination_token = None
                    break
                else:
                    pagination_token = results[-1]["pagination_token"]

            for event in room_events:
                group = room_groups.setdefault(event.room_id, {
                    "results": [],
                })
                group["results"].append(event.event_id)

            if room_events and len(room_events) >= search_filter.limit():
                last_event_id = room_events[-1].event_id
                pagination_token = results_map[last_event_id]["pagination_token"]

                # We want to respect the given batch group and group keys so
                # that if people blindly use the top level `next_batch` token
                # it returns more from the same group (if applicable) rather
                # than reverting to searching all results again.
                if batch_group and batch_group_key:
                    global_next_batch = encode_base64("%s\n%s\n%s" % (
                        batch_group, batch_group_key, pagination_token
                    ))
                else:
                    global_next_batch = encode_base64("%s\n%s\n%s" % (
                        "all", "", pagination_token
                    ))

                for room_id, group in room_groups.items():
                    group["next_batch"] = encode_base64("%s\n%s\n%s" % (
                        "room_id", room_id, pagination_token
                    ))

            allowed_events.extend(room_events)

        else:
            # We should never get here due to the guard earlier.
            raise NotImplementedError()

        # If client has asked for "context" for each event (i.e. some surrounding
        # events and state), fetch that
        if event_context is not None:
            now_token = yield self.hs.get_event_sources().get_current_token()

            contexts = {}
            for event in allowed_events:
                res = yield self.store.get_events_around(
                    event.room_id, event.event_id, before_limit, after_limit
                )

                res["events_before"] = yield filter_events_for_client(
                    self.store, user.to_string(), res["events_before"]
                )

                res["events_after"] = yield filter_events_for_client(
                    self.store, user.to_string(), res["events_after"]
                )

                res["start"] = now_token.copy_and_replace(
                    "room_key", res["start"]
                ).to_string()

                res["end"] = now_token.copy_and_replace(
                    "room_key", res["end"]
                ).to_string()

                if include_profile:
                    senders = set(
                        ev.sender
                        for ev in itertools.chain(
                            res["events_before"], [event], res["events_after"]
                        )
                    )

                    if res["events_after"]:
                        last_event_id = res["events_after"][-1].event_id
                    else:
                        last_event_id = event.event_id

                    state = yield self.store.get_state_for_event(
                        last_event_id,
                        types=[(EventTypes.Member, sender) for sender in senders]
                    )

                    res["profile_info"] = {
                        s.state_key: {
                            "displayname": s.content.get("displayname", None),
                            "avatar_url": s.content.get("avatar_url", None),
                        }
                        for s in state.values()
                        if s.type == EventTypes.Member and s.state_key in senders
                    }

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

        state_results = {}
        if include_state:
            rooms = set(e.room_id for e in allowed_events)
            for room_id in rooms:
                state = yield self.state_handler.get_current_state(room_id)
                state_results[room_id] = state.values()

            state_results.values()

        # We're now about to serialize the events. We should not make any
        # blocking calls after this. Otherwise the 'age' will be wrong

        results = [
            {
                "rank": rank_map[e.event_id],
                "result": serialize_event(e, time_now),
                "context": contexts.get(e.event_id, {}),
            }
            for e in allowed_events
        ]

        rooms_cat_res = {
            "results": results,
            "count": count,
            "highlights": list(highlights),
        }

        if state_results:
            rooms_cat_res["state"] = {
                room_id: [serialize_event(e, time_now) for e in state]
                for room_id, state in state_results.items()
            }

        if room_groups and "room_id" in group_keys:
            rooms_cat_res.setdefault("groups", {})["room_id"] = room_groups

        if sender_group and "sender" in group_keys:
            rooms_cat_res.setdefault("groups", {})["sender"] = sender_group

        if global_next_batch:
            rooms_cat_res["next_batch"] = global_next_batch

        defer.returnValue({
            "search_categories": {
                "room_events": rooms_cat_res
            }
        })
