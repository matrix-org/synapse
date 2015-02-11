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


from twisted.internet import defer
from ._base import BaseHandler

from synapse.api.errors import SynapseError, Codes, CodeMessageException
from synapse.api.constants import EventTypes
from synapse.types import RoomAlias

import logging

logger = logging.getLogger(__name__)


class DirectoryHandler(BaseHandler):

    def __init__(self, hs):
        super(DirectoryHandler, self).__init__(hs)

        self.federation = hs.get_replication_layer()
        self.federation.register_query_handler(
            "directory", self.on_directory_query
        )

    @defer.inlineCallbacks
    def _create_association(self, room_alias, room_id, servers=None):
        # general association creation for both human users and app services

        if not self.hs.is_mine(room_alias):
            raise SynapseError(400, "Room alias must be local")
            # TODO(erikj): Change this.

        # TODO(erikj): Add transactions.
        # TODO(erikj): Check if there is a current association.
        if not servers:
            servers = yield self.store.get_joined_hosts_for_room(room_id)

        if not servers:
            raise SynapseError(400, "Failed to get server list")

        yield self.store.create_room_alias_association(
            room_alias,
            room_id,
            servers
        )

    @defer.inlineCallbacks
    def create_association(self, user_id, room_alias, room_id, servers=None):
        # association creation for human users
        # TODO(erikj): Do user auth.

        can_create = yield self.can_modify_alias(
            room_alias,
            user_id=user_id
        )
        if not can_create:
            raise SynapseError(
                400, "This alias is reserved by an application service.",
                errcode=Codes.EXCLUSIVE
            )
        yield self._create_association(room_alias, room_id, servers)

    @defer.inlineCallbacks
    def create_appservice_association(self, service, room_alias, room_id,
                                      servers=None):
        if not service.is_interested_in_alias(room_alias.to_string()):
            raise SynapseError(
                400, "This application service has not reserved"
                " this kind of alias.", errcode=Codes.EXCLUSIVE
            )

        # association creation for app services
        yield self._create_association(room_alias, room_id, servers)

    @defer.inlineCallbacks
    def delete_association(self, user_id, room_alias):
        # association deletion for human users

        # TODO Check if server admin

        can_delete = yield self.can_modify_alias(
            room_alias,
            user_id=user_id
        )
        if not can_delete:
            raise SynapseError(
                400, "This alias is reserved by an application service.",
                errcode=Codes.EXCLUSIVE
            )

        yield self._delete_association(room_alias)

    @defer.inlineCallbacks
    def delete_appservice_association(self, service, room_alias):
        if not service.is_interested_in_alias(room_alias.to_string()):
            raise SynapseError(
                400,
                "This application service has not reserved this kind of alias",
                errcode=Codes.EXCLUSIVE
            )
        yield self._delete_association(room_alias)

    @defer.inlineCallbacks
    def _delete_association(self, room_alias):
        if not self.hs.is_mine(room_alias):
            raise SynapseError(400, "Room alias must be local")

        yield self.store.delete_room_alias(room_alias)

        # TODO - Looks like _update_room_alias_event has never been implemented
        # if room_id:
        #    yield self._update_room_alias_events(user_id, room_id)

    @defer.inlineCallbacks
    def get_association(self, room_alias):
        room_id = None
        if self.hs.is_mine(room_alias):
            result = yield self.get_association_from_room_alias(
                room_alias
            )

            if result:
                room_id = result.room_id
                servers = result.servers
        else:
            try:
                result = yield self.federation.make_query(
                    destination=room_alias.domain,
                    query_type="directory",
                    args={
                        "room_alias": room_alias.to_string(),
                    },
                    retry_on_dns_fail=False,
                )
            except CodeMessageException as e:
                logging.warn("Error retrieving alias")
                if e.code == 404:
                    result = None
                else:
                    raise

            if result and "room_id" in result and "servers" in result:
                room_id = result["room_id"]
                servers = result["servers"]

        if not room_id:
            raise SynapseError(
                404,
                "Room alias %r not found" % (room_alias.to_string(),),
                Codes.NOT_FOUND
            )

        extra_servers = yield self.store.get_joined_hosts_for_room(room_id)
        servers = set(extra_servers) | set(servers)

        # If this server is in the list of servers, return it first.
        if self.server_name in servers:
            servers = (
                [self.server_name]
                + [s for s in servers if s != self.server_name]
            )
        else:
            servers = list(servers)

        defer.returnValue({
            "room_id": room_id,
            "servers": servers,
        })
        return

    @defer.inlineCallbacks
    def on_directory_query(self, args):
        room_alias = RoomAlias.from_string(args["room_alias"])
        if not self.hs.is_mine(room_alias):
            raise SynapseError(
                400, "Room Alias is not hosted on this Home Server"
            )

        result = yield self.get_association_from_room_alias(
            room_alias
        )

        if result is not None:
            defer.returnValue({
                "room_id": result.room_id,
                "servers": result.servers,
            })
        else:
            raise SynapseError(
                404,
                "Room alias %r not found" % (room_alias.to_string(),),
                Codes.NOT_FOUND
            )

    @defer.inlineCallbacks
    def send_room_alias_update_event(self, user_id, room_id):
        aliases = yield self.store.get_aliases_for_room(room_id)

        msg_handler = self.hs.get_handlers().message_handler
        yield msg_handler.create_and_send_event({
            "type": EventTypes.Aliases,
            "state_key": self.hs.hostname,
            "room_id": room_id,
            "sender": user_id,
            "content": {"aliases": aliases},
        }, ratelimit=False)

    @defer.inlineCallbacks
    def get_association_from_room_alias(self, room_alias):
        result = yield self.store.get_association_from_room_alias(
            room_alias
        )
        if not result:
            # Query AS to see if it exists
            as_handler = self.hs.get_handlers().appservice_handler
            result = yield as_handler.query_room_alias_exists(room_alias)
        defer.returnValue(result)

    @defer.inlineCallbacks
    def can_modify_alias(self, alias, user_id=None):
        services = yield self.store.get_app_services()
        interested_services = [
            s for s in services if s.is_interested_in_alias(alias.to_string())
        ]
        for service in interested_services:
            if user_id == service.sender:
                # this user IS the app service
                defer.returnValue(True)
                return
        defer.returnValue(len(interested_services) == 0)
