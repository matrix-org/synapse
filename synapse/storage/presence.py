# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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
from synapse.util.caches.descriptors import cached, cachedList

from twisted.internet import defer


class PresenceStore(SQLBaseStore):
    def create_presence(self, user_localpart):
        res = self._simple_insert(
            table="presence",
            values={"user_id": user_localpart},
            desc="create_presence",
        )

        self.get_presence_state.invalidate((user_localpart,))
        return res

    def has_presence_state(self, user_localpart):
        return self._simple_select_one(
            table="presence",
            keyvalues={"user_id": user_localpart},
            retcols=["user_id"],
            allow_none=True,
            desc="has_presence_state",
        )

    @cached(max_entries=2000)
    def get_presence_state(self, user_localpart):
        return self._simple_select_one(
            table="presence",
            keyvalues={"user_id": user_localpart},
            retcols=["state", "status_msg", "mtime"],
            desc="get_presence_state",
        )

    @cachedList(get_presence_state.cache, list_name="user_localparts",
                inlineCallbacks=True)
    def get_presence_states(self, user_localparts):
        rows = yield self._simple_select_many_batch(
            table="presence",
            column="user_id",
            iterable=user_localparts,
            retcols=("user_id", "state", "status_msg", "mtime",),
            desc="get_presence_states",
        )

        defer.returnValue({
            row["user_id"]: {
                "state": row["state"],
                "status_msg": row["status_msg"],
                "mtime": row["mtime"],
            }
            for row in rows
        })

    def set_presence_state(self, user_localpart, new_state):
        res = self._simple_update_one(
            table="presence",
            keyvalues={"user_id": user_localpart},
            updatevalues={"state": new_state["state"],
                          "status_msg": new_state["status_msg"],
                          "mtime": self._clock.time_msec()},
            desc="set_presence_state",
        )

        self.get_presence_state.invalidate((user_localpart,))
        return res

    def allow_presence_visible(self, observed_localpart, observer_userid):
        return self._simple_insert(
            table="presence_allow_inbound",
            values={"observed_user_id": observed_localpart,
                    "observer_user_id": observer_userid},
            desc="allow_presence_visible",
            or_ignore=True,
        )

    def disallow_presence_visible(self, observed_localpart, observer_userid):
        return self._simple_delete_one(
            table="presence_allow_inbound",
            keyvalues={"observed_user_id": observed_localpart,
                       "observer_user_id": observer_userid},
            desc="disallow_presence_visible",
        )

    def is_presence_visible(self, observed_localpart, observer_userid):
        return self._simple_select_one(
            table="presence_allow_inbound",
            keyvalues={"observed_user_id": observed_localpart,
                       "observer_user_id": observer_userid},
            retcols=["observed_user_id"],
            allow_none=True,
            desc="is_presence_visible",
        )

    def add_presence_list_pending(self, observer_localpart, observed_userid):
        return self._simple_insert(
            table="presence_list",
            values={"user_id": observer_localpart,
                    "observed_user_id": observed_userid,
                    "accepted": False},
            desc="add_presence_list_pending",
        )

    @defer.inlineCallbacks
    def set_presence_list_accepted(self, observer_localpart, observed_userid):
        result = yield self._simple_update_one(
            table="presence_list",
            keyvalues={"user_id": observer_localpart,
                       "observed_user_id": observed_userid},
            updatevalues={"accepted": True},
            desc="set_presence_list_accepted",
        )
        self.get_presence_list_accepted.invalidate((observer_localpart,))
        defer.returnValue(result)

    def get_presence_list(self, observer_localpart, accepted=None):
        if accepted:
            return self.get_presence_list_accepted(observer_localpart)
        else:
            keyvalues = {"user_id": observer_localpart}
            if accepted is not None:
                keyvalues["accepted"] = accepted

            return self._simple_select_list(
                table="presence_list",
                keyvalues=keyvalues,
                retcols=["observed_user_id", "accepted"],
                desc="get_presence_list",
            )

    @cached()
    def get_presence_list_accepted(self, observer_localpart):
        return self._simple_select_list(
            table="presence_list",
            keyvalues={"user_id": observer_localpart, "accepted": True},
            retcols=["observed_user_id", "accepted"],
            desc="get_presence_list_accepted",
        )

    @defer.inlineCallbacks
    def del_presence_list(self, observer_localpart, observed_userid):
        yield self._simple_delete_one(
            table="presence_list",
            keyvalues={"user_id": observer_localpart,
                       "observed_user_id": observed_userid},
            desc="del_presence_list",
        )
        self.get_presence_list_accepted.invalidate((observer_localpart,))
