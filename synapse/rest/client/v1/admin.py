# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
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

import hashlib
import hmac
import logging

from six import text_type
from six.moves import http_client

from twisted.internet import defer

from synapse.api.constants import Membership
from synapse.api.errors import AuthError, Codes, NotFoundError, SynapseError
from synapse.http.servlet import (
    assert_params_in_dict,
    parse_integer,
    parse_json_object_from_request,
    parse_string,
)
from synapse.types import UserID, create_requester

from .base import ClientV1RestServlet, client_path_patterns

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


class UserRegisterServlet(ClientV1RestServlet):
    """
    Attributes:
         NONCE_TIMEOUT (int): Seconds until a generated nonce won't be accepted
         nonces (dict[str, int]): The nonces that we will accept. A dict of
             nonce to the time it was generated, in int seconds.
    """
    PATTERNS = client_path_patterns("/admin/register")
    NONCE_TIMEOUT = 60

    def __init__(self, hs):
        super(UserRegisterServlet, self).__init__(hs)
        self.handlers = hs.get_handlers()
        self.reactor = hs.get_reactor()
        self.nonces = {}
        self.hs = hs

    def _clear_old_nonces(self):
        """
        Clear out old nonces that are older than NONCE_TIMEOUT.
        """
        now = int(self.reactor.seconds())

        for k, v in list(self.nonces.items()):
            if now - v > self.NONCE_TIMEOUT:
                del self.nonces[k]

    def on_GET(self, request):
        """
        Generate a new nonce.
        """
        self._clear_old_nonces()

        nonce = self.hs.get_secrets().token_hex(64)
        self.nonces[nonce] = int(self.reactor.seconds())
        return (200, {"nonce": nonce})

    @defer.inlineCallbacks
    def on_POST(self, request):
        self._clear_old_nonces()

        if not self.hs.config.registration_shared_secret:
            raise SynapseError(400, "Shared secret registration is not enabled")

        body = parse_json_object_from_request(request)

        if "nonce" not in body:
            raise SynapseError(
                400, "nonce must be specified", errcode=Codes.BAD_JSON,
            )

        nonce = body["nonce"]

        if nonce not in self.nonces:
            raise SynapseError(
                400, "unrecognised nonce",
            )

        # Delete the nonce, so it can't be reused, even if it's invalid
        del self.nonces[nonce]

        if "username" not in body:
            raise SynapseError(
                400, "username must be specified", errcode=Codes.BAD_JSON,
            )
        else:
            if (
                not isinstance(body['username'], text_type)
                or len(body['username']) > 512
            ):
                raise SynapseError(400, "Invalid username")

            username = body["username"].encode("utf-8")
            if b"\x00" in username:
                raise SynapseError(400, "Invalid username")

        if "password" not in body:
            raise SynapseError(
                400, "password must be specified", errcode=Codes.BAD_JSON,
            )
        else:
            if (
                not isinstance(body['password'], text_type)
                or len(body['password']) > 512
            ):
                raise SynapseError(400, "Invalid password")

            password = body["password"].encode("utf-8")
            if b"\x00" in password:
                raise SynapseError(400, "Invalid password")

        admin = body.get("admin", None)
        got_mac = body["mac"]

        want_mac = hmac.new(
            key=self.hs.config.registration_shared_secret.encode(),
            digestmod=hashlib.sha1,
        )
        want_mac.update(nonce.encode('utf8'))
        want_mac.update(b"\x00")
        want_mac.update(username)
        want_mac.update(b"\x00")
        want_mac.update(password)
        want_mac.update(b"\x00")
        want_mac.update(b"admin" if admin else b"notadmin")
        want_mac = want_mac.hexdigest()

        if not hmac.compare_digest(
                want_mac.encode('ascii'),
                got_mac.encode('ascii')
        ):
            raise SynapseError(403, "HMAC incorrect")

        # Reuse the parts of RegisterRestServlet to reduce code duplication
        from synapse.rest.client.v2_alpha.register import RegisterRestServlet

        register = RegisterRestServlet(self.hs)

        (user_id, _) = yield register.registration_handler.register(
            localpart=body['username'].lower(),
            password=body["password"],
            admin=bool(admin),
            generate_token=False,
        )

        result = yield register._create_registration_details(user_id, body)
        defer.returnValue((200, result))


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

        before_ts = parse_integer(request, "before_ts", required=True)
        logger.info("before_ts: %r", before_ts)

        ret = yield self.media_repository.delete_old_remote_media(before_ts)

        defer.returnValue((200, ret))


class PurgeHistoryRestServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns(
        "/admin/purge_history/(?P<room_id>[^/]*)(/(?P<event_id>[^/]+))?"
    )

    def __init__(self, hs):
        """

        Args:
            hs (synapse.server.HomeServer)
        """
        super(PurgeHistoryRestServlet, self).__init__(hs)
        self.pagination_handler = hs.get_pagination_handler()
        self.store = hs.get_datastore()

    @defer.inlineCallbacks
    def on_POST(self, request, room_id, event_id):
        requester = yield self.auth.get_user_by_req(request)
        is_admin = yield self.auth.is_server_admin(requester.user)

        if not is_admin:
            raise AuthError(403, "You are not a server admin")

        body = parse_json_object_from_request(request, allow_empty_body=True)

        delete_local_events = bool(body.get("delete_local_events", False))

        # establish the topological ordering we should keep events from. The
        # user can provide an event_id in the URL or the request body, or can
        # provide a timestamp in the request body.
        if event_id is None:
            event_id = body.get('purge_up_to_event_id')

        if event_id is not None:
            event = yield self.store.get_event(event_id)

            if event.room_id != room_id:
                raise SynapseError(400, "Event is for wrong room.")

            token = yield self.store.get_topological_token_for_event(event_id)

            logger.info(
                "[purge] purging up to token %s (event_id %s)",
                token, event_id,
            )
        elif 'purge_up_to_ts' in body:
            ts = body['purge_up_to_ts']
            if not isinstance(ts, int):
                raise SynapseError(
                    400, "purge_up_to_ts must be an int",
                    errcode=Codes.BAD_JSON,
                )

            stream_ordering = (
                yield self.store.find_first_stream_ordering_after_ts(ts)
            )

            r = (
                yield self.store.get_room_event_after_stream_ordering(
                    room_id, stream_ordering,
                )
            )
            if not r:
                logger.warn(
                    "[purge] purging events not possible: No event found "
                    "(received_ts %i => stream_ordering %i)",
                    ts, stream_ordering,
                )
                raise SynapseError(
                    404,
                    "there is no event to be purged",
                    errcode=Codes.NOT_FOUND,
                )
            (stream, topo, _event_id) = r
            token = "t%d-%d" % (topo, stream)
            logger.info(
                "[purge] purging up to token %s (received_ts %i => "
                "stream_ordering %i)",
                token, ts, stream_ordering,
            )
        else:
            raise SynapseError(
                400,
                "must specify purge_up_to_event_id or purge_up_to_ts",
                errcode=Codes.BAD_JSON,
            )

        purge_id = yield self.pagination_handler.start_purge_history(
            room_id, token,
            delete_local_events=delete_local_events,
        )

        defer.returnValue((200, {
            "purge_id": purge_id,
        }))


class PurgeHistoryStatusRestServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns(
        "/admin/purge_history_status/(?P<purge_id>[^/]+)"
    )

    def __init__(self, hs):
        """

        Args:
            hs (synapse.server.HomeServer)
        """
        super(PurgeHistoryStatusRestServlet, self).__init__(hs)
        self.pagination_handler = hs.get_pagination_handler()

    @defer.inlineCallbacks
    def on_GET(self, request, purge_id):
        requester = yield self.auth.get_user_by_req(request)
        is_admin = yield self.auth.is_server_admin(requester.user)

        if not is_admin:
            raise AuthError(403, "You are not a server admin")

        purge_status = self.pagination_handler.get_purge_status(purge_id)
        if purge_status is None:
            raise NotFoundError("purge id '%s' not found" % purge_id)

        defer.returnValue((200, purge_status.asdict()))


class DeactivateAccountRestServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns("/admin/deactivate/(?P<target_user_id>[^/]*)")

    def __init__(self, hs):
        super(DeactivateAccountRestServlet, self).__init__(hs)
        self._deactivate_account_handler = hs.get_deactivate_account_handler()

    @defer.inlineCallbacks
    def on_POST(self, request, target_user_id):
        body = parse_json_object_from_request(request, allow_empty_body=True)
        erase = body.get("erase", False)
        if not isinstance(erase, bool):
            raise SynapseError(
                http_client.BAD_REQUEST,
                "Param 'erase' must be a boolean, if given",
                Codes.BAD_JSON,
            )

        UserID.from_string(target_user_id)
        requester = yield self.auth.get_user_by_req(request)
        is_admin = yield self.auth.is_server_admin(requester.user)

        if not is_admin:
            raise AuthError(403, "You are not a server admin")

        result = yield self._deactivate_account_handler.deactivate_account(
            target_user_id, erase,
        )
        if result:
            id_server_unbind_result = "success"
        else:
            id_server_unbind_result = "no-support"

        defer.returnValue((200, {
            "id_server_unbind_result": id_server_unbind_result,
        }))


class ShutdownRoomRestServlet(ClientV1RestServlet):
    """Shuts down a room by removing all local users from the room and blocking
    all future invites and joins to the room. Any local aliases will be repointed
    to a new room created by `new_room_user_id` and kicked users will be auto
    joined to the new room.
    """
    PATTERNS = client_path_patterns("/admin/shutdown_room/(?P<room_id>[^/]+)")

    DEFAULT_MESSAGE = (
        "Sharing illegal content on this server is not permitted and rooms in"
        " violation will be blocked."
    )

    def __init__(self, hs):
        super(ShutdownRoomRestServlet, self).__init__(hs)
        self.store = hs.get_datastore()
        self.state = hs.get_state_handler()
        self._room_creation_handler = hs.get_room_creation_handler()
        self.event_creation_handler = hs.get_event_creation_handler()
        self.room_member_handler = hs.get_room_member_handler()

    @defer.inlineCallbacks
    def on_POST(self, request, room_id):
        requester = yield self.auth.get_user_by_req(request)
        is_admin = yield self.auth.is_server_admin(requester.user)
        if not is_admin:
            raise AuthError(403, "You are not a server admin")

        content = parse_json_object_from_request(request)
        assert_params_in_dict(content, ["new_room_user_id"])
        new_room_user_id = content["new_room_user_id"]

        room_creator_requester = create_requester(new_room_user_id)

        message = content.get("message", self.DEFAULT_MESSAGE)
        room_name = content.get("room_name", "Content Violation Notification")

        info = yield self._room_creation_handler.create_room(
            room_creator_requester,
            config={
                "preset": "public_chat",
                "name": room_name,
                "power_level_content_override": {
                    "users_default": -10,
                },
            },
            ratelimit=False,
        )
        new_room_id = info["room_id"]

        yield self.event_creation_handler.create_and_send_nonmember_event(
            room_creator_requester,
            {
                "type": "m.room.message",
                "content": {"body": message, "msgtype": "m.text"},
                "room_id": new_room_id,
                "sender": new_room_user_id,
            },
            ratelimit=False,
        )

        requester_user_id = requester.user.to_string()

        logger.info("Shutting down room %r", room_id)

        yield self.store.block_room(room_id, requester_user_id)

        users = yield self.state.get_current_user_in_room(room_id)
        kicked_users = []
        for user_id in users:
            if not self.hs.is_mine_id(user_id):
                continue

            logger.info("Kicking %r from %r...", user_id, room_id)

            target_requester = create_requester(user_id)
            yield self.room_member_handler.update_membership(
                requester=target_requester,
                target=target_requester.user,
                room_id=room_id,
                action=Membership.LEAVE,
                content={},
                ratelimit=False
            )

            yield self.room_member_handler.forget(target_requester.user, room_id)

            yield self.room_member_handler.update_membership(
                requester=target_requester,
                target=target_requester.user,
                room_id=new_room_id,
                action=Membership.JOIN,
                content={},
                ratelimit=False
            )

            kicked_users.append(user_id)

        aliases_for_room = yield self.store.get_aliases_for_room(room_id)

        yield self.store.update_aliases_for_room(
            room_id, new_room_id, requester_user_id
        )

        defer.returnValue((200, {
            "kicked_users": kicked_users,
            "local_aliases": aliases_for_room,
            "new_room_id": new_room_id,
        }))


class QuarantineMediaInRoom(ClientV1RestServlet):
    """Quarantines all media in a room so that no one can download it via
    this server.
    """
    PATTERNS = client_path_patterns("/admin/quarantine_media/(?P<room_id>[^/]+)")

    def __init__(self, hs):
        super(QuarantineMediaInRoom, self).__init__(hs)
        self.store = hs.get_datastore()

    @defer.inlineCallbacks
    def on_POST(self, request, room_id):
        requester = yield self.auth.get_user_by_req(request)
        is_admin = yield self.auth.is_server_admin(requester.user)
        if not is_admin:
            raise AuthError(403, "You are not a server admin")

        num_quarantined = yield self.store.quarantine_media_ids_in_room(
            room_id, requester.user.to_string(),
        )

        defer.returnValue((200, {"num_quarantined": num_quarantined}))


class ListMediaInRoom(ClientV1RestServlet):
    """Lists all of the media in a given room.
    """
    PATTERNS = client_path_patterns("/admin/room/(?P<room_id>[^/]+)/media")

    def __init__(self, hs):
        super(ListMediaInRoom, self).__init__(hs)
        self.store = hs.get_datastore()

    @defer.inlineCallbacks
    def on_GET(self, request, room_id):
        requester = yield self.auth.get_user_by_req(request)
        is_admin = yield self.auth.is_server_admin(requester.user)
        if not is_admin:
            raise AuthError(403, "You are not a server admin")

        local_mxcs, remote_mxcs = yield self.store.get_media_mxcs_in_room(room_id)

        defer.returnValue((200, {"local": local_mxcs, "remote": remote_mxcs}))


class ResetPasswordRestServlet(ClientV1RestServlet):
    """Post request to allow an administrator reset password for a user.
    This needs user to have administrator access in Synapse.
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
        self._set_password_handler = hs.get_set_password_handler()

    @defer.inlineCallbacks
    def on_POST(self, request, target_user_id):
        """Post request to allow an administrator reset password for a user.
        This needs user to have administrator access in Synapse.
        """
        UserID.from_string(target_user_id)
        requester = yield self.auth.get_user_by_req(request)
        is_admin = yield self.auth.is_server_admin(requester.user)

        if not is_admin:
            raise AuthError(403, "You are not a server admin")

        params = parse_json_object_from_request(request)
        assert_params_in_dict(params, ["new_password"])
        new_password = params['new_password']

        logger.info("new_password: %r", new_password)

        yield self._set_password_handler.set_password(
            target_user_id, new_password, requester
        )
        defer.returnValue((200, {}))


class GetUsersPaginatedRestServlet(ClientV1RestServlet):
    """Get request to get specific number of users from Synapse.
    This needs user to have administrator access in Synapse.
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
        This needs user to have administrator access in Synapse.
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
        start = parse_integer(request, "start", required=True)
        limit = parse_integer(request, "limit", required=True)

        logger.info("limit: %s, start: %s", limit, start)

        ret = yield self.handlers.admin_handler.get_users_paginate(
            order, start, limit
        )
        defer.returnValue((200, ret))

    @defer.inlineCallbacks
    def on_POST(self, request, target_user_id):
        """Post request to get specific number of users from Synapse..
        This needs user to have administrator access in Synapse.
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
        assert_params_in_dict(params, ["limit", "start"])
        limit = params['limit']
        start = params['start']
        logger.info("limit: %s, start: %s", limit, start)

        ret = yield self.handlers.admin_handler.get_users_paginate(
            order, start, limit
        )
        defer.returnValue((200, ret))


class SearchUsersRestServlet(ClientV1RestServlet):
    """Get request to search user table for specific users according to
    search term.
    This needs user to have administrator access in Synapse.
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
        This needs user to have a administrator access in Synapse.
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

        term = parse_string(request, "term", required=True)
        logger.info("term: %s ", term)

        ret = yield self.handlers.admin_handler.search_users(
            term
        )
        defer.returnValue((200, ret))


def register_servlets(hs, http_server):
    WhoisRestServlet(hs).register(http_server)
    PurgeMediaCacheRestServlet(hs).register(http_server)
    PurgeHistoryStatusRestServlet(hs).register(http_server)
    DeactivateAccountRestServlet(hs).register(http_server)
    PurgeHistoryRestServlet(hs).register(http_server)
    UsersRestServlet(hs).register(http_server)
    ResetPasswordRestServlet(hs).register(http_server)
    GetUsersPaginatedRestServlet(hs).register(http_server)
    SearchUsersRestServlet(hs).register(http_server)
    ShutdownRoomRestServlet(hs).register(http_server)
    QuarantineMediaInRoom(hs).register(http_server)
    ListMediaInRoom(hs).register(http_server)
    UserRegisterServlet(hs).register(http_server)
