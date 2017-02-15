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

from twisted.internet import defer

from synapse.api.errors import AuthError, SynapseError
from synapse.types import UserID
from synapse.http.servlet import parse_json_object_from_request

from .base import ClientV1RestServlet, client_path_patterns

import logging

logger = logging.getLogger(__name__)


class UsersRestServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns("/admin/users/(?P<user_id>[^/]*)")

    def __init__(self, hs):
        super(UsersRestServlet, self).__init__(hs)
        self.handlers = hs.get_handlers()

    @defer.inlineCallbacks
    def on_GET(self, request, user_id):
        target_user = UserID.from_string(user_id)
        requester = yield self.auth.get_user_by_req(request)
        is_admin = yield self.auth.is_server_admin(requester.user)

        if not is_admin:
            raise AuthError(403, "You are not a server admin")

        # To allow all users to get the users list
        # if not is_admin and target_user != auth_user:
        #     raise AuthError(403, "You are not a server admin")

        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "Can only users a local user")

        ret = yield self.handlers.admin_handler.get_users()

        defer.returnValue((200, ret))


class WhoisRestServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns("/admin/whois/(?P<user_id>[^/]*)")

    def __init__(self, hs):
        super(WhoisRestServlet, self).__init__(hs)
        self.handlers = hs.get_handlers()

    @defer.inlineCallbacks
    def on_GET(self, request, user_id):
        target_user = UserID.from_string(user_id)
        requester = yield self.auth.get_user_by_req(request)
        auth_user = requester.user
        is_admin = yield self.auth.is_server_admin(requester.user)

        if not is_admin and target_user != auth_user:
            raise AuthError(403, "You are not a server admin")

        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "Can only whois a local user")

        ret = yield self.handlers.admin_handler.get_whois(target_user)

        defer.returnValue((200, ret))


class PurgeMediaCacheRestServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns("/admin/purge_media_cache")

    def __init__(self, hs):
        self.media_repository = hs.get_media_repository()
        super(PurgeMediaCacheRestServlet, self).__init__(hs)

    @defer.inlineCallbacks
    def on_POST(self, request):
        requester = yield self.auth.get_user_by_req(request)
        is_admin = yield self.auth.is_server_admin(requester.user)

        if not is_admin:
            raise AuthError(403, "You are not a server admin")

        before_ts = request.args.get("before_ts", None)
        if not before_ts:
            raise SynapseError(400, "Missing 'before_ts' arg")

        logger.info("before_ts: %r", before_ts[0])

        try:
            before_ts = int(before_ts[0])
        except Exception:
            raise SynapseError(400, "Invalid 'before_ts' arg")

        ret = yield self.media_repository.delete_old_remote_media(before_ts)

        defer.returnValue((200, ret))


class PurgeHistoryRestServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns(
        "/admin/purge_history/(?P<room_id>[^/]*)/(?P<event_id>[^/]*)"
    )

    def __init__(self, hs):
        super(PurgeHistoryRestServlet, self).__init__(hs)
        self.handlers = hs.get_handlers()

    @defer.inlineCallbacks
    def on_POST(self, request, room_id, event_id):
        requester = yield self.auth.get_user_by_req(request)
        is_admin = yield self.auth.is_server_admin(requester.user)

        if not is_admin:
            raise AuthError(403, "You are not a server admin")

        yield self.handlers.message_handler.purge_history(room_id, event_id)

        defer.returnValue((200, {}))


class DeactivateAccountRestServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns("/admin/deactivate/(?P<target_user_id>[^/]*)")

    def __init__(self, hs):
        self.store = hs.get_datastore()
        super(DeactivateAccountRestServlet, self).__init__(hs)

    @defer.inlineCallbacks
    def on_POST(self, request, target_user_id):
        UserID.from_string(target_user_id)
        requester = yield self.auth.get_user_by_req(request)
        is_admin = yield self.auth.is_server_admin(requester.user)

        if not is_admin:
            raise AuthError(403, "You are not a server admin")

        # FIXME: Theoretically there is a race here wherein user resets password
        # using threepid.
        yield self.store.user_delete_access_tokens(target_user_id)
        yield self.store.user_delete_threepids(target_user_id)
        yield self.store.user_set_password_hash(target_user_id, None)

        defer.returnValue((200, {}))


class ResetPasswordRestServlet(ClientV1RestServlet):
    """Post request to allow an administrator reset password for a user.
    This need a user have a administrator access in Synapse.
        Example:
            http://localhost:8008/_matrix/client/api/v1/admin/reset_password/
            @user:to_reset_password?access_token=admin_access_token
        JsonBodyToSend:
            {
                "new_password": "secret"
            }
        Returns:
            200 OK with empty object if success otherwise an error.
        """
    PATTERNS = client_path_patterns("/admin/reset_password/(?P<target_user_id>[^/]*)")

    def __init__(self, hs):
        self.store = hs.get_datastore()
        super(ResetPasswordRestServlet, self).__init__(hs)
        self.hs = hs
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_auth_handler()

    @defer.inlineCallbacks
    def on_POST(self, request, target_user_id):
        """Post request to allow an administrator reset password for a user.
        This need a user have a administrator access in Synapse.
        """
        UserID.from_string(target_user_id)
        requester = yield self.auth.get_user_by_req(request)
        is_admin = yield self.auth.is_server_admin(requester.user)

        if not is_admin:
            raise AuthError(403, "You are not a server admin")

        params = parse_json_object_from_request(request)
        new_password = params['new_password']
        if not new_password:
            raise SynapseError(400, "Missing 'new_password' arg")

        logger.info("new_password: %r", new_password)

        yield self.auth_handler.set_password(
            target_user_id, new_password, requester
        )
        defer.returnValue((200, {}))


class GetUsersPaginatedRestServlet(ClientV1RestServlet):
    """Get request to get specific number of users from Synapse.
    This need a user have a administrator access in Synapse.
        Example:
            http://localhost:8008/_matrix/client/api/v1/admin/users_paginate/
            @admin:user?access_token=admin_access_token&start=0&limit=10
        Returns:
            200 OK with json object {list[dict[str, Any]], count} or empty object.
        """
    PATTERNS = client_path_patterns("/admin/users_paginate/(?P<target_user_id>[^/]*)")

    def __init__(self, hs):
        self.store = hs.get_datastore()
        super(GetUsersPaginatedRestServlet, self).__init__(hs)
        self.hs = hs
        self.auth = hs.get_auth()
        self.handlers = hs.get_handlers()

    @defer.inlineCallbacks
    def on_GET(self, request, target_user_id):
        """Get request to get specific number of users from Synapse.
        This need a user have a administrator access in Synapse.
        """
        target_user = UserID.from_string(target_user_id)
        requester = yield self.auth.get_user_by_req(request)
        is_admin = yield self.auth.is_server_admin(requester.user)

        if not is_admin:
            raise AuthError(403, "You are not a server admin")

        # To allow all users to get the users list
        # if not is_admin and target_user != auth_user:
        #     raise AuthError(403, "You are not a server admin")

        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "Can only users a local user")

        order = "name"  # order by name in user table
        start = request.args.get("start")[0]
        limit = request.args.get("limit")[0]
        if not limit:
            raise SynapseError(400, "Missing 'limit' arg")
        if not start:
            raise SynapseError(400, "Missing 'start' arg")
        logger.info("limit: %s, start: %s", limit, start)

        ret = yield self.handlers.admin_handler.get_users_paginate(
            order, start, limit
        )
        defer.returnValue((200, ret))

    @defer.inlineCallbacks
    def on_POST(self, request, target_user_id):
        """Post request to get specific number of users from Synapse..
        This need a user have a administrator access in Synapse.
        Example:
            http://localhost:8008/_matrix/client/api/v1/admin/users_paginate/
            @admin:user?access_token=admin_access_token
        JsonBodyToSend:
            {
                "start": "0",
                "limit": "10
            }
        Returns:
            200 OK with json object {list[dict[str, Any]], count} or empty object.
        """
        UserID.from_string(target_user_id)
        requester = yield self.auth.get_user_by_req(request)
        is_admin = yield self.auth.is_server_admin(requester.user)

        if not is_admin:
            raise AuthError(403, "You are not a server admin")

        order = "name"  # order by name in user table
        params = parse_json_object_from_request(request)
        limit = params['limit']
        start = params['start']
        if not limit:
            raise SynapseError(400, "Missing 'limit' arg")
        if not start:
            raise SynapseError(400, "Missing 'start' arg")
        logger.info("limit: %s, start: %s", limit, start)

        ret = yield self.handlers.admin_handler.get_users_paginate(
            order, start, limit
        )
        defer.returnValue((200, ret))


class SearchUsersRestServlet(ClientV1RestServlet):
    """Get request to search user table for specific users according to
    search term.
    This need a user have a administrator access in Synapse.
        Example:
            http://localhost:8008/_matrix/client/api/v1/admin/search_users/
            @admin:user?access_token=admin_access_token&term=alice
        Returns:
            200 OK with json object {list[dict[str, Any]], count} or empty object.
    """
    PATTERNS = client_path_patterns("/admin/search_users/(?P<target_user_id>[^/]*)")

    def __init__(self, hs):
        self.store = hs.get_datastore()
        super(SearchUsersRestServlet, self).__init__(hs)
        self.hs = hs
        self.auth = hs.get_auth()
        self.handlers = hs.get_handlers()

    @defer.inlineCallbacks
    def on_GET(self, request, target_user_id):
        """Get request to search user table for specific users according to
        search term.
        This need a user have a administrator access in Synapse.
        """
        target_user = UserID.from_string(target_user_id)
        requester = yield self.auth.get_user_by_req(request)
        is_admin = yield self.auth.is_server_admin(requester.user)

        if not is_admin:
            raise AuthError(403, "You are not a server admin")

        # To allow all users to get the users list
        # if not is_admin and target_user != auth_user:
        #     raise AuthError(403, "You are not a server admin")

        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "Can only users a local user")

        term = request.args.get("term")[0]
        if not term:
            raise SynapseError(400, "Missing 'term' arg")

        logger.info("term: %s ", term)

        ret = yield self.handlers.admin_handler.search_users(
            term
        )
        defer.returnValue((200, ret))


def register_servlets(hs, http_server):
    WhoisRestServlet(hs).register(http_server)
    PurgeMediaCacheRestServlet(hs).register(http_server)
    DeactivateAccountRestServlet(hs).register(http_server)
    PurgeHistoryRestServlet(hs).register(http_server)
    UsersRestServlet(hs).register(http_server)
    ResetPasswordRestServlet(hs).register(http_server)
    GetUsersPaginatedRestServlet(hs).register(http_server)
    SearchUsersRestServlet(hs).register(http_server)
