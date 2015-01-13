# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
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


class PresenceStore(SQLBaseStore):
    def create_presence(self, user_localpart):
        return self._simple_insert(
            table="presence",
            values={"user_id": user_localpart},
        )

    def has_presence_state(self, user_localpart):
        return self._simple_select_one(
            table="presence",
            keyvalues={"user_id": user_localpart},
            retcols=["user_id"],
            allow_none=True,
        )

    def get_presence_state(self, user_localpart):
        return self._simple_select_one(
            table="presence",
            keyvalues={"user_id": user_localpart},
            retcols=["state", "status_msg", "mtime"],
        )

    def set_presence_state(self, user_localpart, new_state):
        return self._simple_update_one(
            table="presence",
            keyvalues={"user_id": user_localpart},
            updatevalues={"state": new_state["state"],
                          "status_msg": new_state["status_msg"],
                          "mtime": self._clock.time_msec()},
            retcols=["state"],
        )

    def allow_presence_visible(self, observed_localpart, observer_userid):
        return self._simple_insert(
            table="presence_allow_inbound",
            values={"observed_user_id": observed_localpart,
                    "observer_user_id": observer_userid},
        )

    def disallow_presence_visible(self, observed_localpart, observer_userid):
        return self._simple_delete_one(
            table="presence_allow_inbound",
            keyvalues={"observed_user_id": observed_localpart,
                       "observer_user_id": observer_userid},
        )

    def is_presence_visible(self, observed_localpart, observer_userid):
        return self._simple_select_one(
            table="presence_allow_inbound",
            keyvalues={"observed_user_id": observed_localpart,
                       "observer_user_id": observer_userid},
            retcols=["observed_user_id"],
            allow_none=True,
        )

    def add_presence_list_pending(self, observer_localpart, observed_userid):
        return self._simple_insert(
            table="presence_list",
            values={"user_id": observer_localpart,
                    "observed_user_id": observed_userid,
                    "accepted": False},
        )

    def set_presence_list_accepted(self, observer_localpart, observed_userid):
        return self._simple_update_one(
            table="presence_list",
            keyvalues={"user_id": observer_localpart,
                       "observed_user_id": observed_userid},
            updatevalues={"accepted": True},
        )

    def get_presence_list(self, observer_localpart, accepted=None):
        keyvalues = {"user_id": observer_localpart}
        if accepted is not None:
            keyvalues["accepted"] = accepted

        return self._simple_select_list(
            table="presence_list",
            keyvalues=keyvalues,
            retcols=["observed_user_id", "accepted"],
        )

    def del_presence_list(self, observer_localpart, observed_userid):
        return self._simple_delete_one(
            table="presence_list",
            keyvalues={"user_id": observer_localpart,
                       "observed_user_id": observed_userid},
        )
