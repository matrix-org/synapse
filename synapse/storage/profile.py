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


class ProfileStore(SQLBaseStore):
    def create_profile(self, user_localpart):
        return self._simple_insert(
            table="profiles",
            values={"user_id": user_localpart},
            desc="create_profile",
        )

    def get_profile_displayname(self, user_localpart):
        return self._simple_select_one_onecol(
            table="profiles",
            keyvalues={"user_id": user_localpart},
            retcol="displayname",
            desc="get_profile_displayname",
        )

    def set_profile_displayname(self, user_localpart, new_displayname):
        return self._simple_update_one(
            table="profiles",
            keyvalues={"user_id": user_localpart},
            updatevalues={"displayname": new_displayname},
            desc="set_profile_displayname",
        )

    def get_profile_avatar_url(self, user_localpart):
        return self._simple_select_one_onecol(
            table="profiles",
            keyvalues={"user_id": user_localpart},
            retcol="avatar_url",
            desc="get_profile_avatar_url",
        )

    def set_profile_avatar_url(self, user_localpart, new_avatar_url):
        return self._simple_update_one(
            table="profiles",
            keyvalues={"user_id": user_localpart},
            updatevalues={"avatar_url": new_avatar_url},
            desc="set_profile_avatar_url",
        )
