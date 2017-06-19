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

from twisted.internet import defer

from ._base import SQLBaseStore

import ujson as json


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

    def is_user_admin_in_group(self, group_id, user_id):
        return self._simple_select_one_onecol(
            table="group_users",
            keyvalues={
                "group_id": group_id,
                "user_id": user_id,
            },
            retcol="is_admin",
            allow_none=True,
            desc="is_user_adim_in_group",
        )

    def add_group_invite(self, group_id, user_id):
        return self._simple_insert(
            table="group_invites",
            values={
                "group_id": group_id,
                "user_id": user_id,
            },
            desc="add_group_invite",
        )

    def is_user_invited_to_local_group(self, group_id, user_id):
        return self._simple_select_one_onecol(
            table="group_invites",
            keyvalues={
                "group_id": group_id,
                "user_id": user_id,
            },
            retcol="user_id",
            desc="is_user_invited_to_local_group",
            allow_none=True,
        )

    def add_user_to_group(self, group_id, user_id, is_admin=False, is_public=True,
                          assestation=None, valid_until_ms=None):
        def _add_user_to_group_txn(txn):
            self._simple_insert_txn(
                txn,
                table="group_users",
                values={
                    "group_id": group_id,
                    "user_id": user_id,
                    "is_admin": is_admin,
                    "is_public": is_public,
                    "assestation": json.dumps(assestation),
                },
            )

            self._simple_delete_txn(
                txn,
                table="group_invites",
                keyvalues={
                    "group_id": group_id,
                    "user_id": user_id,
                },
            )

            if valid_until_ms:
                self._simple_insert_txn(
                    txn,
                    table="group_assestations_renewals",
                    values={
                        "group_id": group_id,
                        "user_id": user_id,
                        "valid_until_ms": valid_until_ms,
                    },
                )

        return self.runInteraction(
            "add_user_to_group", _add_user_to_group_txn
        )

    def remove_user_to_group(self, group_id, user_id):
        def _remove_user_to_group_txn(txn):
            self._simple_delete_txn(
                txn,
                table="group_users",
                keyvalues={
                    "group_id": group_id,
                    "user_id": user_id,
                },
            )
            self._simple_delete_txn(
                txn,
                table="group_invites",
                keyvalues={
                    "group_id": group_id,
                    "user_id": user_id,
                },
            )
            self._simple_delete_txn(
                txn,
                table="group_assestations_renewals",
                keyvalues={
                    "group_id": group_id,
                    "user_id": user_id,
                },
            )
        return self.runInteraction("remove_user_to_group", _remove_user_to_group_txn)

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

    @defer.inlineCallbacks
    def register_user_group_membership(self, group_id, user_id, membership,
                                       is_admin=False, assestation=None,
                                       valid_until_ms=None):
        def _register_user_group_membership_txn(txn, next_id):
            self._simple_delete_txn(
                txn,
                table="local_group_membership",
                keyvalues={
                    "group_id": group_id,
                    "user_id": user_id,
                },
            )
            self._simple_insert_txn(
                txn,
                table="local_group_membership",
                values={
                    "stream_id": next_id,
                    "group_id": group_id,
                    "user_id": user_id,
                    "is_admin": is_admin,
                    "membership": membership,
                },
            )
            if valid_until_ms and membership == "join":
                self._simple_insert_txn(
                    txn,
                    table="group_assestations_renewals",
                    values={
                        "group_id": group_id,
                        "user_id": user_id,
                        "valid_until_ms": valid_until_ms,
                    },
                )
            elif membership != "join":
                self._simple_delete_txn(
                    txn,
                    table="group_assestations_renewals",
                    keyvalues={
                        "group_id": group_id,
                        "user_id": user_id,
                    },
                )

        with self._group_membership_id_gen.get_next() as next_id:
            yield self.runInteraction(
                "register_user_group_membership",
                _register_user_group_membership_txn, next_id,
            )

    @defer.inlineCallbacks
    def create_group(self, group_id, user_id, name, avatar_url, short_description,
                     long_description,):
        yield self._simple_insert(
            table="groups",
            values={
                "group_id": group_id,
                "name": name,
                "avatar_url": avatar_url,
                "short_description": short_description,
                "long_description": long_description,
            },
            desc="create_group",
        )

    def get_joined_groups(self, user_id):
        return self._simple_select_onecol(
            table="local_group_membership",
            keyvalues={
                "user_id": user_id,
                "membership": "join",
            },
            retcol="group_id",
            desc="get_joined_groups",
        )
