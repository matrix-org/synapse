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

import logging
import string
from typing import Iterable, List, Optional

from twisted.internet import defer

from synapse.api.constants import MAX_ALIAS_LENGTH, EventTypes
from synapse.api.errors import (
    AuthError,
    CodeMessageException,
    Codes,
    NotFoundError,
    StoreError,
    SynapseError,
)
from synapse.appservice import ApplicationService
from synapse.types import Requester, RoomAlias, UserID, get_domain_from_id

from ._base import BaseHandler

logger = logging.getLogger(__name__)


class DirectoryHandler(BaseHandler):
    def __init__(self, hs):
        super(DirectoryHandler, self).__init__(hs)

        self.state = hs.get_state_handler()
        self.appservice_handler = hs.get_application_service_handler()
        self.event_creation_handler = hs.get_event_creation_handler()
        self.store = hs.get_datastore()
        self.config = hs.config
        self.enable_room_list_search = hs.config.enable_room_list_search
        self.require_membership = hs.config.require_membership_for_aliases

        self.federation = hs.get_federation_client()
        hs.get_federation_registry().register_query_handler(
            "directory", self.on_directory_query
        )

        self.spam_checker = hs.get_spam_checker()

    @defer.inlineCallbacks
    def _create_association(
        self,
        room_alias: RoomAlias,
        room_id: str,
        servers: Optional[Iterable[str]] = None,
        creator: Optional[str] = None,
    ):
        # general association creation for both human users and app services

        for wchar in string.whitespace:
            if wchar in room_alias.localpart:
                raise SynapseError(400, "Invalid characters in room alias")

        if not self.hs.is_mine(room_alias):
            raise SynapseError(400, "Room alias must be local")
            # TODO(erikj): Change this.

        # TODO(erikj): Add transactions.
        # TODO(erikj): Check if there is a current association.
        if not servers:
            users = yield self.state.get_current_users_in_room(room_id)
            servers = {get_domain_from_id(u) for u in users}

        if not servers:
            raise SynapseError(400, "Failed to get server list")

        yield self.store.create_room_alias_association(
            room_alias, room_id, servers, creator=creator
        )

    async def create_association(
        self,
        requester: Requester,
        room_alias: RoomAlias,
        room_id: str,
        servers: Optional[List[str]] = None,
        check_membership: bool = True,
    ):
        """Attempt to create a new alias

        Args:
            requester
            room_alias
            room_id
            servers: Iterable of servers that others servers should try and join via
            check_membership: Whether to check if the user is in the room
                before the alias can be set (if the server's config requires it).

        Returns:
            Deferred
        """

        user_id = requester.user.to_string()

        if len(room_alias.to_string()) > MAX_ALIAS_LENGTH:
            raise SynapseError(
                400,
                "Can't create aliases longer than %s characters" % MAX_ALIAS_LENGTH,
                Codes.INVALID_PARAM,
            )

        service = requester.app_service
        if service:
            if not service.is_interested_in_alias(room_alias.to_string()):
                raise SynapseError(
                    400,
                    "This application service has not reserved this kind of alias.",
                    errcode=Codes.EXCLUSIVE,
                )
        else:
            # Server admins are not subject to the same constraints as normal
            # users when creating an alias (e.g. being in the room).
            is_admin = await self.auth.is_server_admin(requester.user)

            if (self.require_membership and check_membership) and not is_admin:
                rooms_for_user = await self.store.get_rooms_for_user(user_id)
                if room_id not in rooms_for_user:
                    raise AuthError(
                        403, "You must be in the room to create an alias for it"
                    )

            if not self.spam_checker.user_may_create_room_alias(user_id, room_alias):
                raise AuthError(403, "This user is not permitted to create this alias")

            if not self.config.is_alias_creation_allowed(
                user_id, room_id, room_alias.to_string()
            ):
                # Lets just return a generic message, as there may be all sorts of
                # reasons why we said no. TODO: Allow configurable error messages
                # per alias creation rule?
                raise SynapseError(403, "Not allowed to create alias")

            can_create = await self.can_modify_alias(room_alias, user_id=user_id)
            if not can_create:
                raise AuthError(
                    400,
                    "This alias is reserved by an application service.",
                    errcode=Codes.EXCLUSIVE,
                )

        await self._create_association(room_alias, room_id, servers, creator=user_id)

    async def delete_association(self, requester: Requester, room_alias: RoomAlias):
        """Remove an alias from the directory

        (this is only meant for human users; AS users should call
        delete_appservice_association)

        Args:
            requester
            room_alias

        Returns:
            Deferred[unicode]: room id that the alias used to point to

        Raises:
            NotFoundError: if the alias doesn't exist

            AuthError: if the user doesn't have perms to delete the alias (ie, the user
                is neither the creator of the alias, nor a server admin.

            SynapseError: if the alias belongs to an AS
        """
        user_id = requester.user.to_string()

        try:
            can_delete = await self._user_can_delete_alias(room_alias, user_id)
        except StoreError as e:
            if e.code == 404:
                raise NotFoundError("Unknown room alias")
            raise

        if not can_delete:
            raise AuthError(403, "You don't have permission to delete the alias.")

        can_delete = await self.can_modify_alias(room_alias, user_id=user_id)
        if not can_delete:
            raise SynapseError(
                400,
                "This alias is reserved by an application service.",
                errcode=Codes.EXCLUSIVE,
            )

        room_id = await self._delete_association(room_alias)

        try:
            await self._update_canonical_alias(requester, user_id, room_id, room_alias)
        except AuthError as e:
            logger.info("Failed to update alias events: %s", e)

        return room_id

    @defer.inlineCallbacks
    def delete_appservice_association(
        self, service: ApplicationService, room_alias: RoomAlias
    ):
        if not service.is_interested_in_alias(room_alias.to_string()):
            raise SynapseError(
                400,
                "This application service has not reserved this kind of alias",
                errcode=Codes.EXCLUSIVE,
            )
        yield self._delete_association(room_alias)

    @defer.inlineCallbacks
    def _delete_association(self, room_alias: RoomAlias):
        if not self.hs.is_mine(room_alias):
            raise SynapseError(400, "Room alias must be local")

        room_id = yield self.store.delete_room_alias(room_alias)

        return room_id

    @defer.inlineCallbacks
    def get_association(self, room_alias: RoomAlias):
        room_id = None
        if self.hs.is_mine(room_alias):
            result = yield self.get_association_from_room_alias(room_alias)

            if result:
                room_id = result.room_id
                servers = result.servers
        else:
            try:
                result = yield self.federation.make_query(
                    destination=room_alias.domain,
                    query_type="directory",
                    args={"room_alias": room_alias.to_string()},
                    retry_on_dns_fail=False,
                    ignore_backoff=True,
                )
            except CodeMessageException as e:
                logging.warning("Error retrieving alias")
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
                "Room alias %s not found" % (room_alias.to_string(),),
                Codes.NOT_FOUND,
            )

        users = yield self.state.get_current_users_in_room(room_id)
        extra_servers = {get_domain_from_id(u) for u in users}
        servers = set(extra_servers) | set(servers)

        # If this server is in the list of servers, return it first.
        if self.server_name in servers:
            servers = [self.server_name] + [s for s in servers if s != self.server_name]
        else:
            servers = list(servers)

        return {"room_id": room_id, "servers": servers}

    @defer.inlineCallbacks
    def on_directory_query(self, args):
        room_alias = RoomAlias.from_string(args["room_alias"])
        if not self.hs.is_mine(room_alias):
            raise SynapseError(400, "Room Alias is not hosted on this homeserver")

        result = yield self.get_association_from_room_alias(room_alias)

        if result is not None:
            return {"room_id": result.room_id, "servers": result.servers}
        else:
            raise SynapseError(
                404,
                "Room alias %r not found" % (room_alias.to_string(),),
                Codes.NOT_FOUND,
            )

    async def _update_canonical_alias(
        self, requester: Requester, user_id: str, room_id: str, room_alias: RoomAlias
    ):
        """
        Send an updated canonical alias event if the removed alias was set as
        the canonical alias or listed in the alt_aliases field.
        """
        alias_event = await self.state.get_current_state(
            room_id, EventTypes.CanonicalAlias, ""
        )

        # There is no canonical alias, nothing to do.
        if not alias_event:
            return

        # Obtain a mutable version of the event content.
        content = dict(alias_event.content)
        send_update = False

        # Remove the alias property if it matches the removed alias.
        alias_str = room_alias.to_string()
        if alias_event.content.get("alias", "") == alias_str:
            send_update = True
            content.pop("alias", "")

        # Filter the alt_aliases property for the removed alias. Note that the
        # value is not modified if alt_aliases is of an unexpected form.
        alt_aliases = content.get("alt_aliases")
        if isinstance(alt_aliases, (list, tuple)) and alias_str in alt_aliases:
            send_update = True
            alt_aliases = [alias for alias in alt_aliases if alias != alias_str]

            if alt_aliases:
                content["alt_aliases"] = alt_aliases
            else:
                del content["alt_aliases"]

        if send_update:
            await self.event_creation_handler.create_and_send_nonmember_event(
                requester,
                {
                    "type": EventTypes.CanonicalAlias,
                    "state_key": "",
                    "room_id": room_id,
                    "sender": user_id,
                    "content": content,
                },
                ratelimit=False,
            )

    @defer.inlineCallbacks
    def get_association_from_room_alias(self, room_alias: RoomAlias):
        result = yield self.store.get_association_from_room_alias(room_alias)
        if not result:
            # Query AS to see if it exists
            as_handler = self.appservice_handler
            result = yield as_handler.query_room_alias_exists(room_alias)
        return result

    def can_modify_alias(self, alias: RoomAlias, user_id: Optional[str] = None):
        # Any application service "interested" in an alias they are regexing on
        # can modify the alias.
        # Users can only modify the alias if ALL the interested services have
        # non-exclusive locks on the alias (or there are no interested services)
        services = self.store.get_app_services()
        interested_services = [
            s for s in services if s.is_interested_in_alias(alias.to_string())
        ]

        for service in interested_services:
            if user_id == service.sender:
                # this user IS the app service so they can do whatever they like
                return defer.succeed(True)
            elif service.is_exclusive_alias(alias.to_string()):
                # another service has an exclusive lock on this alias.
                return defer.succeed(False)
        # either no interested services, or no service with an exclusive lock
        return defer.succeed(True)

    async def _user_can_delete_alias(self, alias: RoomAlias, user_id: str):
        """Determine whether a user can delete an alias.

        One of the following must be true:

        1. The user created the alias.
        2. The user is a server administrator.
        3. The user has a power-level sufficient to send a canonical alias event
           for the current room.

        """
        creator = await self.store.get_room_alias_creator(alias.to_string())

        if creator is not None and creator == user_id:
            return True

        # Resolve the alias to the corresponding room.
        room_mapping = await self.get_association(alias)
        room_id = room_mapping["room_id"]
        if not room_id:
            return False

        res = await self.auth.check_can_change_room_list(
            room_id, UserID.from_string(user_id)
        )
        return res

    async def edit_published_room_list(
        self, requester: Requester, room_id: str, visibility: str
    ):
        """Edit the entry of the room in the published room list.

        requester
        room_id
        visibility: "public" or "private"
        """
        user_id = requester.user.to_string()

        if not self.spam_checker.user_may_publish_room(user_id, room_id):
            raise AuthError(
                403, "This user is not permitted to publish rooms to the room list"
            )

        if requester.is_guest:
            raise AuthError(403, "Guests cannot edit the published room list")

        if visibility not in ["public", "private"]:
            raise SynapseError(400, "Invalid visibility setting")

        if visibility == "public" and not self.enable_room_list_search:
            # The room list has been disabled.
            raise AuthError(
                403, "This user is not permitted to publish rooms to the room list"
            )

        room = await self.store.get_room(room_id)
        if room is None:
            raise SynapseError(400, "Unknown room")

        can_change_room_list = await self.auth.check_can_change_room_list(
            room_id, requester.user
        )
        if not can_change_room_list:
            raise AuthError(
                403,
                "This server requires you to be a moderator in the room to"
                " edit its room list entry",
            )

        making_public = visibility == "public"
        if making_public:
            room_aliases = await self.store.get_aliases_for_room(room_id)
            canonical_alias = await self.store.get_canonical_alias_for_room(room_id)
            if canonical_alias:
                room_aliases.append(canonical_alias)

            if not self.config.is_publishing_room_allowed(
                user_id, room_id, room_aliases
            ):
                # Lets just return a generic message, as there may be all sorts of
                # reasons why we said no. TODO: Allow configurable error messages
                # per alias creation rule?
                raise SynapseError(403, "Not allowed to publish room")

        await self.store.set_room_is_public(room_id, making_public)

    @defer.inlineCallbacks
    def edit_published_appservice_room_list(
        self, appservice_id: str, network_id: str, room_id: str, visibility: str
    ):
        """Add or remove a room from the appservice/network specific public
        room list.

        Args:
            appservice_id: ID of the appservice that owns the list
            network_id: The ID of the network the list is associated with
            room_id
            visibility: either "public" or "private"
        """
        if visibility not in ["public", "private"]:
            raise SynapseError(400, "Invalid visibility setting")

        yield self.store.set_room_is_public_appservice(
            room_id, appservice_id, network_id, visibility == "public"
        )

    async def get_aliases_for_room(
        self, requester: Requester, room_id: str
    ) -> List[str]:
        """
        Get a list of the aliases that currently point to this room on this server
        """
        # allow access to server admins and current members of the room
        is_admin = await self.auth.is_server_admin(requester.user)
        if not is_admin:
            await self.auth.check_user_in_room_or_world_readable(
                room_id, requester.user.to_string()
            )

        aliases = await self.store.get_aliases_for_room(room_id)
        return aliases
