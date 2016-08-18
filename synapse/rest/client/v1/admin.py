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

from .base import ClientV1RestServlet, client_path_patterns

import logging

logger = logging.getLogger(__name__)


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


def register_servlets(hs, http_server):
    WhoisRestServlet(hs).register(http_server)
    PurgeMediaCacheRestServlet(hs).register(http_server)
    DeactivateAccountRestServlet(hs).register(http_server)
    PurgeHistoryRestServlet(hs).register(http_server)
