# -*- coding: utf-8 -*-
# Copyright 2017 Vector Creations Ltd
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


class GroupServerStore(SQLBaseStore):
    def get_group(self, group_id):
        return self._simple_select_one(
            table="groups",
            keyvalues={
                "group_id": group_id,
            },
            retcols=("name", "short_description", "long_description", "avatar_url",),
            allow_none=True,
            desc="is_user_in_group",
        )

    def get_users_in_group(self, group_id, include_private=False):
        # TODO: Pagination

        keyvalues = {
            "group_id": group_id,
        }
        if not include_private:
            keyvalues["is_public"] = True

        return self._simple_select_list(
            table="group_users",
            keyvalues=keyvalues,
            retcols=("user_id", "is_public",),
            desc="get_users_in_group",
        )

    def get_rooms_in_group(self, group_id, include_private=False):
        # TODO: Pagination

        keyvalues = {
            "group_id": group_id,
        }
        if not include_private:
            keyvalues["is_public"] = True

        return self._simple_select_list(
            table="group_rooms",
            keyvalues=keyvalues,
            retcols=("room_id", "is_public",),
            desc="get_rooms_in_group",
        )

    def is_user_in_group(self, user_id, group_id):
        return self._simple_select_one_onecol(
            table="group_users",
            keyvalues={
                "group_id": group_id,
                "user_id": user_id,
            },
            retcol="user_id",
            allow_none=True,
            desc="is_user_in_group",
        ).addCallback(lambda r: bool(r))

    def add_user_to_group(self, group_id, user_id):
        return self._simple_insert(
            table="group_users",
            values={
                "group_id": group_id,
                "user_id": user_id,
            },
            desc="add_user_to_group",
        )

    def add_room_to_group(self, group_id, room_id, is_public):
        return self._simple_insert(
            table="group_rooms",
            values={
                "group_id": group_id,
                "room_id": room_id,
                "is_public": is_public,
            },
            desc="add_room_to_group",
        )
