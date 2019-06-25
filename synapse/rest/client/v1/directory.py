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

from twisted.internet import defer

from synapse.api.errors import AuthError, Codes, NotFoundError, SynapseError
from synapse.http.servlet import RestServlet, parse_json_object_from_request
from synapse.rest.client.v2_alpha._base import client_patterns
from synapse.types import RoomAlias

logger = logging.getLogger(__name__)


def register_servlets(hs, http_server):
    ClientDirectoryServer(hs).register(http_server)
    ClientDirectoryListServer(hs).register(http_server)
    ClientAppserviceDirectoryListServer(hs).register(http_server)


class ClientDirectoryServer(RestServlet):
    PATTERNS = client_patterns("/directory/room/(?P<room_alias>[^/]*)$", v1=True)

    def __init__(self, hs):
        super(ClientDirectoryServer, self).__init__()
        self.store = hs.get_datastore()
        self.handlers = hs.get_handlers()
        self.auth = hs.get_auth()

    @defer.inlineCallbacks
    def on_GET(self, request, room_alias):
        room_alias = RoomAlias.from_string(room_alias)

        dir_handler = self.handlers.directory_handler
        res = yield dir_handler.get_association(room_alias)

        defer.returnValue((200, res))

    @defer.inlineCallbacks
    def on_PUT(self, request, room_alias):
        room_alias = RoomAlias.from_string(room_alias)

        content = parse_json_object_from_request(request)
        if "room_id" not in content:
            raise SynapseError(
                400, 'Missing params: ["room_id"]', errcode=Codes.BAD_JSON
            )

        logger.debug("Got content: %s", content)
        logger.debug("Got room name: %s", room_alias.to_string())

        room_id = content["room_id"]
        servers = content["servers"] if "servers" in content else None

        logger.debug("Got room_id: %s", room_id)
        logger.debug("Got servers: %s", servers)

        # TODO(erikj): Check types.

        room = yield self.store.get_room(room_id)
        if room is None:
            raise SynapseError(400, "Room does not exist")

        requester = yield self.auth.get_user_by_req(request)

        yield self.handlers.directory_handler.create_association(
            requester, room_alias, room_id, servers
        )

        defer.returnValue((200, {}))

    @defer.inlineCallbacks
    def on_DELETE(self, request, room_alias):
        dir_handler = self.handlers.directory_handler

        try:
            service = yield self.auth.get_appservice_by_req(request)
            room_alias = RoomAlias.from_string(room_alias)
            yield dir_handler.delete_appservice_association(service, room_alias)
            logger.info(
                "Application service at %s deleted alias %s",
                service.url,
                room_alias.to_string(),
            )
            defer.returnValue((200, {}))
        except AuthError:
            # fallback to default user behaviour if they aren't an AS
            pass

        requester = yield self.auth.get_user_by_req(request)
        user = requester.user

        room_alias = RoomAlias.from_string(room_alias)

        yield dir_handler.delete_association(requester, room_alias)

        logger.info(
            "User %s deleted alias %s", user.to_string(), room_alias.to_string()
        )

        defer.returnValue((200, {}))


class ClientDirectoryListServer(RestServlet):
    PATTERNS = client_patterns("/directory/list/room/(?P<room_id>[^/]*)$", v1=True)

    def __init__(self, hs):
        super(ClientDirectoryListServer, self).__init__()
        self.store = hs.get_datastore()
        self.handlers = hs.get_handlers()
        self.auth = hs.get_auth()

    @defer.inlineCallbacks
    def on_GET(self, request, room_id):
        room = yield self.store.get_room(room_id)
        if room is None:
            raise NotFoundError("Unknown room")

        defer.returnValue(
            (200, {"visibility": "public" if room["is_public"] else "private"})
        )

    @defer.inlineCallbacks
    def on_PUT(self, request, room_id):
        requester = yield self.auth.get_user_by_req(request)

        content = parse_json_object_from_request(request)
        visibility = content.get("visibility", "public")

        yield self.handlers.directory_handler.edit_published_room_list(
            requester, room_id, visibility
        )

        defer.returnValue((200, {}))

    @defer.inlineCallbacks
    def on_DELETE(self, request, room_id):
        requester = yield self.auth.get_user_by_req(request)

        yield self.handlers.directory_handler.edit_published_room_list(
            requester, room_id, "private"
        )

        defer.returnValue((200, {}))


class ClientAppserviceDirectoryListServer(RestServlet):
    PATTERNS = client_patterns(
        "/directory/list/appservice/(?P<network_id>[^/]*)/(?P<room_id>[^/]*)$", v1=True
    )

    def __init__(self, hs):
        super(ClientAppserviceDirectoryListServer, self).__init__()
        self.store = hs.get_datastore()
        self.handlers = hs.get_handlers()
        self.auth = hs.get_auth()

    def on_PUT(self, request, network_id, room_id):
        content = parse_json_object_from_request(request)
        visibility = content.get("visibility", "public")
        return self._edit(request, network_id, room_id, visibility)

    def on_DELETE(self, request, network_id, room_id):
        return self._edit(request, network_id, room_id, "private")

    @defer.inlineCallbacks
    def _edit(self, request, network_id, room_id, visibility):
        requester = yield self.auth.get_user_by_req(request)
        if not requester.app_service:
            raise AuthError(
                403, "Only appservices can edit the appservice published room list"
            )

        yield self.handlers.directory_handler.edit_published_appservice_room_list(
            requester.app_service.id, network_id, room_id, visibility
        )

        defer.returnValue((200, {}))
