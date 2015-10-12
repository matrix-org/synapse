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

from synapse.api.constants import KnownRoomEventKeys, SearchConstraintTypes
from synapse.api.errors import SynapseError
from synapse.events.utils import serialize_event

import logging


logger = logging.getLogger(__name__)


KEYS_TO_ALLOWED_CONSTRAINT_TYPES = {
    KnownRoomEventKeys.CONTENT_BODY: [SearchConstraintTypes.FTS],
    KnownRoomEventKeys.CONTENT_MSGTYPE: [SearchConstraintTypes.EXACT],
    KnownRoomEventKeys.CONTENT_NAME: [SearchConstraintTypes.FTS, SearchConstraintTypes.EXACT, SearchConstraintTypes.SUBSTRING],
    KnownRoomEventKeys.CONTENT_TOPIC: [SearchConstraintTypes.FTS],
    KnownRoomEventKeys.SENDER: [SearchConstraintTypes.EXACT],
    KnownRoomEventKeys.ORIGIN_SERVER_TS: [SearchConstraintTypes.RANGE],
    KnownRoomEventKeys.ROOM_ID: [SearchConstraintTypes.EXACT],
}


class RoomConstraint(object):
    def __init__(self, search_type, keys, value):
        self.search_type = search_type
        self.keys = keys
        self.value = value

    @classmethod
    def from_dict(cls, d):
        search_type = d["type"]
        keys = d["keys"]

        for key in keys:
            if key not in KEYS_TO_ALLOWED_CONSTRAINT_TYPES:
                raise SynapseError(400, "Unrecognized key %r", key)

            if search_type not in KEYS_TO_ALLOWED_CONSTRAINT_TYPES[key]:
                raise SynapseError(400, "Disallowed constraint type %r for key %r", search_type, key)

        return cls(search_type, keys, d["value"])


class SearchHandler(BaseHandler):

    def __init__(self, hs):
        super(SearchHandler, self).__init__(hs)

    @defer.inlineCallbacks
    def search(self, user, content):
        constraint_dicts = content["search_categories"]["room_events"]["constraints"]
        constraints = [RoomConstraint.from_dict(c)for c in constraint_dicts]

        fts = False
        for c in constraints:
            if c.search_type == SearchConstraintTypes.FTS:
                if fts:
                    raise SynapseError(400, "Only one constraint can be FTS")
                fts = True

        rooms = yield self.store.get_rooms_for_user(
            user.to_string(),
        )

        # For some reason the list of events contains duplicates
        # TODO(paul): work out why because I really don't think it should
        room_ids = set(r.room_id for r in rooms)

        res = yield self.store.search_msgs(room_ids, constraints)

        time_now = self.clock.time_msec()

        results = {
            r["result"].event_id: {
                "rank": r["rank"],
                "result": serialize_event(r["result"], time_now)
            }
            for r in res
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
