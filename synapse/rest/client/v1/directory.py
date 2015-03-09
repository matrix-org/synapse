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

from synapse.api.errors import AuthError, SynapseError, Codes
from synapse.types import RoomAlias
from .base import ClientV1RestServlet, client_path_pattern

import simplejson as json
import logging


logger = logging.getLogger(__name__)


def register_servlets(hs, http_server):
    ClientDirectoryServer(hs).register(http_server)


class ClientDirectoryServer(ClientV1RestServlet):
    PATTERN = client_path_pattern("/directory/room/(?P<room_alias>[^/]*)$")

    @defer.inlineCallbacks
    def on_GET(self, request, room_alias):
        room_alias = RoomAlias.from_string(room_alias)

        dir_handler = self.handlers.directory_handler
        res = yield dir_handler.get_association(room_alias)

        defer.returnValue((200, res))

    @defer.inlineCallbacks
    def on_PUT(self, request, room_alias):
        content = _parse_json(request)
        if "room_id" not in content:
            raise SynapseError(400, "Missing room_id key",
                               errcode=Codes.BAD_JSON)

        logger.debug("Got content: %s", content)

        room_alias = RoomAlias.from_string(room_alias)

        logger.debug("Got room name: %s", room_alias.to_string())

        room_id = content["room_id"]
        servers = content["servers"] if "servers" in content else None

        logger.debug("Got room_id: %s", room_id)
        logger.debug("Got servers: %s", servers)

        # TODO(erikj): Check types.
        # TODO(erikj): Check that room exists

        dir_handler = self.handlers.directory_handler

        try:
            # try to auth as a user
            user, client = yield self.auth.get_user_by_req(request)
            try:
                user_id = user.to_string()
                yield dir_handler.create_association(
                    user_id, room_alias, room_id, servers
                )
                yield dir_handler.send_room_alias_update_event(user_id, room_id)
            except SynapseError as e:
                raise e
            except:
                logger.exception("Failed to create association")
                raise
        except AuthError:
            # try to auth as an application service
            service = yield self.auth.get_appservice_by_req(request)
            yield dir_handler.create_appservice_association(
                service, room_alias, room_id, servers
            )
            logger.info(
                "Application service at %s created alias %s pointing to %s",
                service.url,
                room_alias.to_string(),
                room_id
            )

        defer.returnValue((200, {}))

    @defer.inlineCallbacks
    def on_DELETE(self, request, room_alias):
        dir_handler = self.handlers.directory_handler

        try:
            service = yield self.auth.get_appservice_by_req(request)
            room_alias = RoomAlias.from_string(room_alias)
            yield dir_handler.delete_appservice_association(
                service, room_alias
            )
            logger.info(
                "Application service at %s deleted alias %s",
                service.url,
                room_alias.to_string()
            )
            defer.returnValue((200, {}))
        except AuthError:
            # fallback to default user behaviour if they aren't an AS
            pass

        user, client = yield self.auth.get_user_by_req(request)

        is_admin = yield self.auth.is_server_admin(user)
        if not is_admin:
            raise AuthError(403, "You need to be a server admin")

        room_alias = RoomAlias.from_string(room_alias)

        yield dir_handler.delete_association(
            user.to_string(), room_alias
        )
        logger.info(
            "User %s deleted alias %s",
            user.to_string(),
            room_alias.to_string()
        )

        defer.returnValue((200, {}))


def _parse_json(request):
    try:
        content = json.loads(request.content.read())
        if type(content) != dict:
            raise SynapseError(400, "Content must be a JSON object.",
                               errcode=Codes.NOT_JSON)
        return content
    except ValueError:
        raise SynapseError(400, "Content not JSON.", errcode=Codes.NOT_JSON)
