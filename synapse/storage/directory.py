# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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


RoomAliasMapping = namedtuple(
    "RoomAliasMapping",
    ("room_id", "room_alias", "servers",)
)


class DirectoryStore(SQLBaseStore):

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
        )

        if not room_id:
            defer.returnValue(None)
            return

        servers = yield self._simple_select_onecol(
            "room_alias_servers",
            {"room_alias": room_alias.to_string()},
            "server",
        )

        if not servers:
            defer.returnValue(None)
            return

        defer.returnValue(
            RoomAliasMapping(room_id, room_alias.to_string(), servers)
        )

    @defer.inlineCallbacks
    def create_room_alias_association(self, room_alias, room_id, servers):
        """ Creates an associatin between  a room alias and room_id/servers

        Args:
            room_alias (RoomAlias)
            room_id (str)
            servers (list)

        Returns:
            Deferred
        """
        yield self._simple_insert(
            "room_aliases",
            {
                "room_alias": room_alias.to_string(),
                "room_id": room_id,
            },
        )

        for server in servers:
            # TODO(erikj): Fix this to bulk insert
            yield self._simple_insert(
                "room_alias_servers",
                {
                    "room_alias": room_alias.to_string(),
                    "server": server,
                }
            )
