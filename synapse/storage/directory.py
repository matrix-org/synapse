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

from collections import namedtuple

from twisted.internet import defer

from synapse.api.errors import SynapseError
from synapse.util.caches.descriptors import cached

from ._base import SQLBaseStore

RoomAliasMapping = namedtuple(
    "RoomAliasMapping",
    ("room_id", "room_alias", "servers",)
)


class DirectoryWorkerStore(SQLBaseStore):
    @defer.inlineCallbacks
    def get_association_from_room_alias(self, room_alias):
        """ Get's the room_id and server list for a given room_alias

        Args:
            room_alias (RoomAlias)

        Returns:
            Deferred: results in namedtuple with keys "room_id" and
            "servers" or None if no association can be found
        """
        room_id = yield self._simple_select_one_onecol(
            "room_aliases",
            {"room_alias": room_alias.to_string()},
            "room_id",
            allow_none=True,
            desc="get_association_from_room_alias",
        )

        if not room_id:
            defer.returnValue(None)
            return

        servers = yield self._simple_select_onecol(
            "room_alias_servers",
            {"room_alias": room_alias.to_string()},
            "server",
            desc="get_association_from_room_alias",
        )

        if not servers:
            defer.returnValue(None)
            return

        defer.returnValue(
            RoomAliasMapping(room_id, room_alias.to_string(), servers)
        )

    def get_room_alias_creator(self, room_alias):
        return self._simple_select_one_onecol(
            table="room_aliases",
            keyvalues={
                "room_alias": room_alias,
            },
            retcol="creator",
            desc="get_room_alias_creator",
            allow_none=True
        )

    @cached(max_entries=5000)
    def get_aliases_for_room(self, room_id):
        return self._simple_select_onecol(
            "room_aliases",
            {"room_id": room_id},
            "room_alias",
            desc="get_aliases_for_room",
        )


class DirectoryStore(DirectoryWorkerStore):
    @defer.inlineCallbacks
    def create_room_alias_association(self, room_alias, room_id, servers, creator=None):
        """ Creates an associatin between  a room alias and room_id/servers

        Args:
            room_alias (RoomAlias)
            room_id (str)
            servers (list)
            creator (str): Optional user_id of creator.

        Returns:
            Deferred
        """
        def alias_txn(txn):
            self._simple_insert_txn(
                txn,
                "room_aliases",
                {
                    "room_alias": room_alias.to_string(),
                    "room_id": room_id,
                    "creator": creator,
                },
            )

            self._simple_insert_many_txn(
                txn,
                table="room_alias_servers",
                values=[{
                    "room_alias": room_alias.to_string(),
                    "server": server,
                } for server in servers],
            )

            self._invalidate_cache_and_stream(
                txn, self.get_aliases_for_room, (room_id,)
            )

        try:
            ret = yield self.runInteraction(
                "create_room_alias_association", alias_txn
            )
        except self.database_engine.module.IntegrityError:
            raise SynapseError(
                409, "Room alias %s already exists" % room_alias.to_string()
            )
        defer.returnValue(ret)

    @defer.inlineCallbacks
    def delete_room_alias(self, room_alias):
        room_id = yield self.runInteraction(
            "delete_room_alias",
            self._delete_room_alias_txn,
            room_alias,
        )

        defer.returnValue(room_id)

    def _delete_room_alias_txn(self, txn, room_alias):
        txn.execute(
            "SELECT room_id FROM room_aliases WHERE room_alias = ?",
            (room_alias.to_string(),)
        )

        res = txn.fetchone()
        if res:
            room_id = res[0]
        else:
            return None

        txn.execute(
            "DELETE FROM room_aliases WHERE room_alias = ?",
            (room_alias.to_string(),)
        )

        txn.execute(
            "DELETE FROM room_alias_servers WHERE room_alias = ?",
            (room_alias.to_string(),)
        )

        self._invalidate_cache_and_stream(
            txn, self.get_aliases_for_room, (room_id,)
        )

        return room_id

    def update_aliases_for_room(self, old_room_id, new_room_id, creator):
        def _update_aliases_for_room_txn(txn):
            sql = "UPDATE room_aliases SET room_id = ?, creator = ? WHERE room_id = ?"
            txn.execute(sql, (new_room_id, creator, old_room_id,))
            self._invalidate_cache_and_stream(
                txn, self.get_aliases_for_room, (old_room_id,)
            )
            self._invalidate_cache_and_stream(
                txn, self.get_aliases_for_room, (new_room_id,)
            )
        return self.runInteraction(
            "_update_aliases_for_room_txn", _update_aliases_for_room_txn
        )
