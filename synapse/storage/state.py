# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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

from ._base import SQLBaseStore
from twisted.internet import defer

from collections import namedtuple


StateGroup = namedtuple("StateGroup", ("group", "state"))


class StateStore(SQLBaseStore):

    @defer.inlineCallbacks
    def get_state_groups(self, event_ids):
        groups = set()
        for event_id in event_ids:
            group = yield self._simple_select_one_onecol(
                table="event_to_state_groups",
                keyvalues={"event_id": event_id},
                retcol="state_group",
                allow_none=True,
            )
            if group:
                groups.add(group)

        res = []
        for group in groups:
            state_ids = yield self._simple_select_onecol(
                table="state_groups_state",
                keyvalues={"state_group": group},
                retcol="event_id",
            )
            state = []
            for state_id in state_ids:
                s = yield self.get_event(
                    state_id,
                    allow_none=True,
                )
                if s:
                    state.append(s)

            res.append(StateGroup(group, state))

        defer.returnValue(res)

    def store_state_groups(self, event):
        return self.runInteraction(
            self._store_state_groups_txn, event
        )

    def _store_state_groups_txn(self, txn, event):
        state_group = event.state_group
        if not state_group:
            state_group = self._simple_insert_txn(
                txn,
                table="state_groups",
                values={
                    "room_id": event.room_id,
                    "event_id": event.event_id,
                }
            )

            for state in event.state_events:
                self._simple_insert_txn(
                    txn,
                    table="state_groups_state",
                    values={
                        "state_group": state_group,
                        "room_id": state.room_id,
                        "type": state.type,
                        "state_key": state.state_key,
                        "event_id": state.event_id,
                    }
                )

        self._simple_insert_txn(
            txn,
            table="event_to_state_groups",
            values={
                "state_group": state_group,
                "event_id": event.event_id,
            }
        )
