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
from typing import Optional

from twisted.internet import defer

from synapse.api.errors import SynapseError
from synapse.storage._base import SQLBaseStore
from synapse.util.caches.descriptors import cached

RoomAliasMapping = namedtuple("RoomAliasMapping", ("room_id", "room_alias", "servers"))


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
        room_id = yield self.db.simple_select_one_onecol(
            "room_aliases",
            {"room_alias": room_alias.to_string()},
            "room_id",
            allow_none=True,
            desc="get_association_from_room_alias",
        )

        if not room_id:
            return None

        servers = yield self.db.simple_select_onecol(
            "room_alias_servers",
            {"room_alias": room_alias.to_string()},
            "server",
            desc="get_association_from_room_alias",
        )

        if not servers:
            return None

        return RoomAliasMapping(room_id, room_alias.to_string(), servers)

    def get_room_alias_creator(self, room_alias):
        return self.db.simple_select_one_onecol(
            table="room_aliases",
            keyvalues={"room_alias": room_alias},
            retcol="creator",
            desc="get_room_alias_creator",
        )

    @cached(max_entries=5000)
    def get_aliases_for_room(self, room_id):
        return self.db.simple_select_onecol(
            "room_aliases",
            {"room_id": room_id},
            "room_alias",
            desc="get_aliases_for_room",
        )


class DirectoryStore(DirectoryWorkerStore):
    @defer.inlineCallbacks
    def create_room_alias_association(self, room_alias, room_id, servers, creator=None):
        """ Creates an association between a room alias and room_id/servers

        Args:
            room_alias (RoomAlias)
            room_id (str)
            servers (list)
            creator (str): Optional user_id of creator.

        Returns:
            Deferred
        """

        def alias_txn(txn):
            self.db.simple_insert_txn(
                txn,
                "room_aliases",
                {
                    "room_alias": room_alias.to_string(),
                    "room_id": room_id,
                    "creator": creator,
                },
            )

            self.db.simple_insert_many_txn(
                txn,
                table="room_alias_servers",
                values=[
                    {"room_alias": room_alias.to_string(), "server": server}
                    for server in servers
                ],
            )

            self._invalidate_cache_and_stream(
                txn, self.get_aliases_for_room, (room_id,)
            )

        try:
            ret = yield self.db.runInteraction(
                "create_room_alias_association", alias_txn
            )
        except self.database_engine.module.IntegrityError:
            raise SynapseError(
                409, "Room alias %s already exists" % room_alias.to_string()
            )
        return ret

    @defer.inlineCallbacks
    def delete_room_alias(self, room_alias):
        room_id = yield self.db.runInteraction(
            "delete_room_alias", self._delete_room_alias_txn, room_alias
        )

        return room_id

    def _delete_room_alias_txn(self, txn, room_alias):
        txn.execute(
            "SELECT room_id FROM room_aliases WHERE room_alias = ?",
            (room_alias.to_string(),),
        )

        res = txn.fetchone()
        if res:
            room_id = res[0]
        else:
            return None

        txn.execute(
            "DELETE FROM room_aliases WHERE room_alias = ?", (room_alias.to_string(),)
        )

        txn.execute(
            "DELETE FROM room_alias_servers WHERE room_alias = ?",
            (room_alias.to_string(),),
        )

        self._invalidate_cache_and_stream(txn, self.get_aliases_for_room, (room_id,))

        return room_id

    def update_aliases_for_room(
        self, old_room_id: str, new_room_id: str, creator: Optional[str] = None,
    ):
        """Repoint all of the aliases for a given room, to a different room.

        Args:
            old_room_id:
            new_room_id:
            creator: The user to record as the creator of the new mapping.
                If None, the creator will be left unchanged.
        """

        def _update_aliases_for_room_txn(txn):
            update_creator_sql = ""
            sql_params = (new_room_id, old_room_id)
            if creator:
                update_creator_sql = ", creator = ?"
                sql_params = (new_room_id, creator, old_room_id)

            sql = "UPDATE room_aliases SET room_id = ? %s WHERE room_id = ?" % (
                update_creator_sql,
            )
            txn.execute(sql, sql_params)
            self._invalidate_cache_and_stream(
                txn, self.get_aliases_for_room, (old_room_id,)
            )
            self._invalidate_cache_and_stream(
                txn, self.get_aliases_for_room, (new_room_id,)
            )

        return self.db.runInteraction(
            "_update_aliases_for_room_txn", _update_aliases_for_room_txn
        )
