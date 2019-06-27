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

import itertools
import logging

from unpaddedbase64 import decode_base64, encode_base64

from twisted.internet import defer

from synapse.api.constants import EventTypes, Membership
from synapse.api.errors import SynapseError
from synapse.api.filtering import Filter
from synapse.storage.state import StateFilter
from synapse.visibility import filter_events_for_client

from ._base import BaseHandler

logger = logging.getLogger(__name__)


class SearchHandler(BaseHandler):
    def __init__(self, hs):
        super(SearchHandler, self).__init__(hs)
        self._event_serializer = hs.get_event_client_serializer()

    @defer.inlineCallbacks
    def get_old_rooms_from_upgraded_room(self, room_id):
        """Retrieves room IDs of old rooms in the history of an upgraded room.

        We do so by checking the m.room.create event of the room for a
        `predecessor` key. If it exists, we add the room ID to our return
        list and then check that room for a m.room.create event and so on
        until we can no longer find any more previous rooms.

        The full list of all found rooms in then returned.

        Args:
            room_id (str): id of the room to search through.

        Returns:
            Deferred[iterable[unicode]]: predecessor room ids
        """

        historical_room_ids = []

        while True:
            predecessor = yield self.store.get_room_predecessor(room_id)

            # If no predecessor, assume we've hit a dead end
            if not predecessor:
                break

            # Add predecessor's room ID
            historical_room_ids.append(predecessor["room_id"])

            # Scan through the old room for further predecessors
            room_id = predecessor["room_id"]

        defer.returnValue(historical_room_ids)

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

        if not self.hs.config.enable_search:
            raise SynapseError(400, "Search is disabled on this homeserver")

        batch_group = None
        batch_group_key = None
        batch_token = None
        if batch:
            try:
                b = decode_base64(batch).decode("ascii")
                batch_group, batch_group_key, batch_token = b.split("\n")

                assert batch_group is not None
                assert batch_group_key is not None
                assert batch_token is not None
            except Exception:
                raise SynapseError(400, "Invalid batch")

        logger.info(
            "Search batch properties: %r, %r, %r",
            batch_group,
            batch_group_key,
            batch_token,
        )

        logger.info("Search content: %s", content)

        try:
            room_cat = content["search_categories"]["room_events"]

            # The actual thing to query in FTS
            search_term = room_cat["search_term"]

            # Which "keys" to search over in FTS query
            keys = room_cat.get(
                "keys", ["content.body", "content.name", "content.topic"]
            )

            # Filter to apply to results
            filter_dict = room_cat.get("filter", {})

            # What to order results by (impacts whether pagination can be doen)
            order_by = room_cat.get("order_by", "rank")

            # Return the current state of the rooms?
            include_state = room_cat.get("include_state", False)

            # Include context around each event?
            event_context = room_cat.get("event_context", None)

            # Group results together? May allow clients to paginate within a
            # group
            group_by = room_cat.get("groupings", {}).get("group_by", {})
            group_keys = [g["key"] for g in group_by]

            if event_context is not None:
                before_limit = int(event_context.get("before_limit", 5))
                after_limit = int(event_context.get("after_limit", 5))

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
                "Invalid group by keys: %r"
                % (set(group_keys) - {"room_id", "sender"},),
            )

        search_filter = Filter(filter_dict)

        # TODO: Search through left rooms too
        rooms = yield self.store.get_rooms_for_user_where_membership_is(
            user.to_string(),
            membership_list=[Membership.JOIN],
            # membership_list=[Membership.JOIN, Membership.LEAVE, Membership.Ban],
        )
        room_ids = set(r.room_id for r in rooms)

        # If doing a subset of all rooms seearch, check if any of the rooms
        # are from an upgraded room, and search their contents as well
        if search_filter.rooms:
            historical_room_ids = []
            for room_id in search_filter.rooms:
                # Add any previous rooms to the search if they exist
                ids = yield self.get_old_rooms_from_upgraded_room(room_id)
                historical_room_ids += ids

            # Prevent any historical events from being filtered
            search_filter = search_filter.with_room_ids(historical_room_ids)

        room_ids = search_filter.filter_rooms(room_ids)

        if batch_group == "room_id":
            room_ids.intersection_update({batch_group_key})

        if not room_ids:
            defer.returnValue(
                {
                    "search_categories": {
                        "room_events": {"results": [], "count": 0, "highlights": []}
                    }
                }
            )

        rank_map = {}  # event_id -> rank of event
        allowed_events = []
        room_groups = {}  # Holds result of grouping by room, if applicable
        sender_group = {}  # Holds result of grouping by sender, if applicable

        # Holds the next_batch for the entire result set if one of those exists
        global_next_batch = None

        highlights = set()

        count = None

        if order_by == "rank":
            search_result = yield self.store.search_msgs(room_ids, search_term, keys)

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
            allowed_events = events[: search_filter.limit()]

            for e in allowed_events:
                rm = room_groups.setdefault(
                    e.room_id, {"results": [], "order": rank_map[e.event_id]}
                )
                rm["results"].append(e.event_id)

                s = sender_group.setdefault(
                    e.sender, {"results": [], "order": rank_map[e.event_id]}
                )
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
                    room_ids,
                    search_term,
                    keys,
                    search_filter.limit() * 2,
                    pagination_token=pagination_token,
                )

                if search_result["highlights"]:
                    highlights.update(search_result["highlights"])

                count = search_result["count"]

                results = search_result["results"]

                results_map = {r["event"].event_id: r for r in results}

                rank_map.update({r["event"].event_id: r["rank"] for r in results})

                filtered_events = search_filter.filter([r["event"] for r in results])

                events = yield filter_events_for_client(
                    self.store, user.to_string(), filtered_events
                )

                room_events.extend(events)
                room_events = room_events[: search_filter.limit()]

                if len(results) < search_filter.limit() * 2:
                    pagination_token = None
                    break
                else:
                    pagination_token = results[-1]["pagination_token"]

            for event in room_events:
                group = room_groups.setdefault(event.room_id, {"results": []})
                group["results"].append(event.event_id)

            if room_events and len(room_events) >= search_filter.limit():
                last_event_id = room_events[-1].event_id
                pagination_token = results_map[last_event_id]["pagination_token"]

                # We want to respect the given batch group and group keys so
                # that if people blindly use the top level `next_batch` token
                # it returns more from the same group (if applicable) rather
                # than reverting to searching all results again.
                if batch_group and batch_group_key:
                    global_next_batch = encode_base64(
                        (
                            "%s\n%s\n%s"
                            % (batch_group, batch_group_key, pagination_token)
                        ).encode("ascii")
                    )
                else:
                    global_next_batch = encode_base64(
                        ("%s\n%s\n%s" % ("all", "", pagination_token)).encode("ascii")
                    )

                for room_id, group in room_groups.items():
                    group["next_batch"] = encode_base64(
                        ("%s\n%s\n%s" % ("room_id", room_id, pagination_token)).encode(
                            "ascii"
                        )
                    )

            allowed_events.extend(room_events)

        else:
            # We should never get here due to the guard earlier.
            raise NotImplementedError()

        logger.info("Found %d events to return", len(allowed_events))

        # If client has asked for "context" for each event (i.e. some surrounding
        # events and state), fetch that
        if event_context is not None:
            now_token = yield self.hs.get_event_sources().get_current_token()

            contexts = {}
            for event in allowed_events:
                res = yield self.store.get_events_around(
                    event.room_id, event.event_id, before_limit, after_limit
                )

                logger.info(
                    "Context for search returned %d and %d events",
                    len(res["events_before"]),
                    len(res["events_after"]),
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

                    state_filter = StateFilter.from_types(
                        [(EventTypes.Member, sender) for sender in senders]
                    )

                    state = yield self.store.get_state_for_event(
                        last_event_id, state_filter
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
            context["events_before"] = (
                yield self._event_serializer.serialize_events(
                    context["events_before"], time_now
                )
            )
            context["events_after"] = (
                yield self._event_serializer.serialize_events(
                    context["events_after"], time_now
                )
            )

        state_results = {}
        if include_state:
            rooms = set(e.room_id for e in allowed_events)
            for room_id in rooms:
                state = yield self.state_handler.get_current_state(room_id)
                state_results[room_id] = list(state.values())

            state_results.values()

        # We're now about to serialize the events. We should not make any
        # blocking calls after this. Otherwise the 'age' will be wrong

        results = []
        for e in allowed_events:
            results.append(
                {
                    "rank": rank_map[e.event_id],
                    "result": (
                        yield self._event_serializer.serialize_event(e, time_now)
                    ),
                    "context": contexts.get(e.event_id, {}),
                }
            )

        rooms_cat_res = {
            "results": results,
            "count": count,
            "highlights": list(highlights),
        }

        if state_results:
            s = {}
            for room_id, state in state_results.items():
                s[room_id] = yield self._event_serializer.serialize_events(
                    state, time_now
                )

            rooms_cat_res["state"] = s

        if room_groups and "room_id" in group_keys:
            rooms_cat_res.setdefault("groups", {})["room_id"] = room_groups

        if sender_group and "sender" in group_keys:
            rooms_cat_res.setdefault("groups", {})["sender"] = sender_group

        if global_next_batch:
            rooms_cat_res["next_batch"] = global_next_batch

        defer.returnValue({"search_categories": {"room_events": rooms_cat_res}})
