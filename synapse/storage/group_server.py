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
                          local_attestation=None, remote_attestation=None):
        def _add_user_to_group_txn(txn):
            self._simple_insert_txn(
                txn,
                table="group_users",
                values={
                    "group_id": group_id,
                    "user_id": user_id,
                    "is_admin": is_admin,
                    "is_public": is_public,
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

            if local_attestation:
                self._simple_insert_txn(
                    txn,
                    table="group_attestations_renewals",
                    values={
                        "group_id": group_id,
                        "user_id": user_id,
                        "valid_until_ms": local_attestation["valid_until_ms"],
                    },
                )
            if remote_attestation:
                self._simple_insert_txn(
                    txn,
                    table="group_attestations_remote",
                    values={
                        "group_id": group_id,
                        "user_id": user_id,
                        "valid_until_ms": remote_attestation["valid_until_ms"],
                        "attestation": json.dumps(remote_attestation),
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
                table="group_attestations_renewals",
                keyvalues={
                    "group_id": group_id,
                    "user_id": user_id,
                },
            )
            self._simple_delete_txn(
                txn,
                table="group_attestations_remote",
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
                                       is_admin=False, content={},
                                       local_attestation=None,
                                       remote_attestation=None,
                                       ):
        def _register_user_group_membership_txn(txn, next_id):
            # TODO: Upsert?
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
                    "group_id": group_id,
                    "user_id": user_id,
                    "is_admin": is_admin,
                    "membership": membership,
                    "content": json.dumps(content),
                },
            )
            self._simple_delete_txn(
                txn,
                table="local_group_updates",
                keyvalues={
                    "group_id": group_id,
                    "user_id": user_id,
                    "type": "membership",
                },
            )
            self._simple_insert_txn(
                txn,
                table="local_group_updates",
                values={
                    "stream_id": next_id,
                    "group_id": group_id,
                    "user_id": user_id,
                    "type": "membership",
                    "content": json.dumps({"membership": membership, "content": content}),
                }
            )
            self._group_updates_stream_cache.entity_has_changed(user_id, next_id)

            # TODO: Insert profile to ensuer it comes down stream if its a join.

            if membership == "join":
                if local_attestation:
                    self._simple_insert_txn(
                        txn,
                        table="group_attestations_renewals",
                        values={
                            "group_id": group_id,
                            "user_id": user_id,
                            "valid_until_ms": local_attestation["valid_until_ms"],
                        }
                    )
                if remote_attestation:
                    self._simple_insert_txn(
                        txn,
                        table="group_attestations_remote",
                        values={
                            "group_id": group_id,
                            "user_id": user_id,
                            "valid_until_ms": remote_attestation["valid_until_ms"],
                            "attestation": json.dumps(remote_attestation),
                        }
                    )
            else:
                self._simple_delete_txn(
                    txn,
                    table="group_attestations_renewals",
                    keyvalues={
                        "group_id": group_id,
                        "user_id": user_id,
                    },
                )
                self._simple_delete_txn(
                    txn,
                    table="group_attestations_remote",
                    keyvalues={
                        "group_id": group_id,
                        "user_id": user_id,
                    },
                )

        with self._group_updates_id_gen.get_next() as next_id:
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

    def get_all_groups_for_user(self, user_id, now_token):
        def _get_all_groups_for_user_txn(txn):
            sql = """
                SELECT group_id, type, membership, u.content
                FROM local_group_updates AS u
                INNER JOIN local_group_membership USING (group_id, user_id)
                WHERE user_id = ? AND membership != 'leave'
                    AND stream_id <= ?
            """
            txn.execute(sql, (user_id, now_token,))
            return self.cursor_to_dict(txn)
        return self.runInteraction(
            "get_all_groups_for_user", _get_all_groups_for_user_txn,
        )

    def get_groups_changes_for_user(self, user_id, from_token, to_token):
        from_token = int(from_token)
        has_changed = self._group_updates_stream_cache.has_entity_changed(
            user_id, from_token,
        )
        if not has_changed:
            return []

        def _get_groups_changes_for_user_txn(txn):
            sql = """
                SELECT group_id, membership, type, u.content
                FROM local_group_updates AS u
                INNER JOIN local_group_membership USING (group_id, user_id)
                WHERE user_id = ? AND ? < stream_id AND stream_id <= ?
            """
            txn.execute(sql, (user_id, from_token, to_token,))
            return [{
                "group_id": group_id,
                "membership": membership,
                "type": gtype,
                "content": json.loads(content_json),
            } for group_id, membership, gtype, content_json in txn]
        return self.runInteraction(
            "get_groups_changes_for_user", _get_groups_changes_for_user_txn,
        )

    def get_group_stream_token(self):
        return self._group_updates_id_gen.get_current_token()
