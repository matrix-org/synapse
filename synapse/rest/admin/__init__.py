# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018-2019 New Vector Ltd
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
import platform
import re

from six import text_type
from six.moves import http_client

from twisted.internet import defer

import synapse
from synapse.api.constants import Membership, UserTypes
from synapse.api.errors import AuthError, Codes, NotFoundError, SynapseError
from synapse.http.server import JsonResource
from synapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_integer,
    parse_json_object_from_request,
    parse_string,
)
from synapse.rest.admin._base import assert_requester_is_admin, assert_user_is_admin
from synapse.rest.admin.server_notice_servlet import SendServerNoticeServlet
from synapse.types import UserID, create_requester
from synapse.util.versionstring import get_version_string

logger = logging.getLogger(__name__)


def historical_admin_path_patterns(path_regex):
    """Returns the list of patterns for an admin endpoint, including historical ones

    This is a backwards-compatibility hack. Previously, the Admin API was exposed at
    various paths under /_matrix/client. This function returns a list of patterns
    matching those paths (as well as the new one), so that existing scripts which rely
    on the endpoints being available there are not broken.

    Note that this should only be used for existing endpoints: new ones should just
    register for the /_synapse/admin path.
    """
    return list(
        re.compile(prefix + path_regex)
        for prefix in (
            "^/_synapse/admin/v1",
            "^/_matrix/client/api/v1/admin",
            "^/_matrix/client/unstable/admin",
            "^/_matrix/client/r0/admin"
        )
    )


class UsersRestServlet(RestServlet):
    PATTERNS = historical_admin_path_patterns("/users/(?P<user_id>[^/]*)")

    def __init__(self, hs):
        self.hs = hs
        self.auth = hs.get_auth()
        self.handlers = hs.get_handlers()

    @defer.inlineCallbacks
    def on_GET(self, request, user_id):
        target_user = UserID.from_string(user_id)
        yield assert_requester_is_admin(self.auth, request)

        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "Can only users a local user")

        ret = yield self.handlers.admin_handler.get_users()

        defer.returnValue((200, ret))


class VersionServlet(RestServlet):
    PATTERNS = (re.compile("^/_synapse/admin/v1/server_version$"), )

    def __init__(self, hs):
        self.res = {
            'server_version': get_version_string(synapse),
            'python_version': platform.python_version(),
        }

    def on_GET(self, request):
        return 200, self.res


class UserRegisterServlet(RestServlet):
    """
    Attributes:
         NONCE_TIMEOUT (int): Seconds until a generated nonce won't be accepted
         nonces (dict[str, int]): The nonces that we will accept. A dict of
             nonce to the time it was generated, in int seconds.
    """
    PATTERNS = historical_admin_path_patterns("/register")
    NONCE_TIMEOUT = 60

    def __init__(self, hs):
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
        user_type = body.get("user_type", None)

        if user_type is not None and user_type not in UserTypes.ALL_USER_TYPES:
            raise SynapseError(400, "Invalid user type")

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
        if user_type:
            want_mac.update(b"\x00")
            want_mac.update(user_type.encode('utf8'))
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
            user_type=user_type,
        )

        result = yield register._create_registration_details(user_id, body)
        defer.returnValue((200, result))


class WhoisRestServlet(RestServlet):
    PATTERNS = historical_admin_path_patterns("/whois/(?P<user_id>[^/]*)")

    def __init__(self, hs):
        self.hs = hs
        self.auth = hs.get_auth()
        self.handlers = hs.get_handlers()

    @defer.inlineCallbacks
    def on_GET(self, request, user_id):
        target_user = UserID.from_string(user_id)
        requester = yield self.auth.get_user_by_req(request)
        auth_user = requester.user

        if target_user != auth_user:
            yield assert_user_is_admin(self.auth, auth_user)

        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "Can only whois a local user")

        ret = yield self.handlers.admin_handler.get_whois(target_user)

        defer.returnValue((200, ret))


class PurgeMediaCacheRestServlet(RestServlet):
    PATTERNS = historical_admin_path_patterns("/purge_media_cache")

    def __init__(self, hs):
        self.media_repository = hs.get_media_repository()
        self.auth = hs.get_auth()

    @defer.inlineCallbacks
    def on_POST(self, request):
        yield assert_requester_is_admin(self.auth, request)

        before_ts = parse_integer(request, "before_ts", required=True)
        logger.info("before_ts: %r", before_ts)

        ret = yield self.media_repository.delete_old_remote_media(before_ts)

        defer.returnValue((200, ret))


class PurgeHistoryRestServlet(RestServlet):
    PATTERNS = historical_admin_path_patterns(
        "/purge_history/(?P<room_id>[^/]*)(/(?P<event_id>[^/]+))?"
    )

    def __init__(self, hs):
        """

        Args:
            hs (synapse.server.HomeServer)
        """
        self.pagination_handler = hs.get_pagination_handler()
        self.store = hs.get_datastore()
        self.auth = hs.get_auth()

    @defer.inlineCallbacks
    def on_POST(self, request, room_id, event_id):
        yield assert_requester_is_admin(self.auth, request)

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


class PurgeHistoryStatusRestServlet(RestServlet):
    PATTERNS = historical_admin_path_patterns(
        "/purge_history_status/(?P<purge_id>[^/]+)"
    )

    def __init__(self, hs):
        """

        Args:
            hs (synapse.server.HomeServer)
        """
        self.pagination_handler = hs.get_pagination_handler()
        self.auth = hs.get_auth()

    @defer.inlineCallbacks
    def on_GET(self, request, purge_id):
        yield assert_requester_is_admin(self.auth, request)

        purge_status = self.pagination_handler.get_purge_status(purge_id)
        if purge_status is None:
            raise NotFoundError("purge id '%s' not found" % purge_id)

        defer.returnValue((200, purge_status.asdict()))


class DeactivateAccountRestServlet(RestServlet):
    PATTERNS = historical_admin_path_patterns("/deactivate/(?P<target_user_id>[^/]*)")

    def __init__(self, hs):
        self._deactivate_account_handler = hs.get_deactivate_account_handler()
        self.auth = hs.get_auth()

    @defer.inlineCallbacks
    def on_POST(self, request, target_user_id):
        yield assert_requester_is_admin(self.auth, request)
        body = parse_json_object_from_request(request, allow_empty_body=True)
        erase = body.get("erase", False)
        if not isinstance(erase, bool):
            raise SynapseError(
                http_client.BAD_REQUEST,
                "Param 'erase' must be a boolean, if given",
                Codes.BAD_JSON,
            )

        UserID.from_string(target_user_id)

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


class ShutdownRoomRestServlet(RestServlet):
    """Shuts down a room by removing all local users from the room and blocking
    all future invites and joins to the room. Any local aliases will be repointed
    to a new room created by `new_room_user_id` and kicked users will be auto
    joined to the new room.
    """
    PATTERNS = historical_admin_path_patterns("/shutdown_room/(?P<room_id>[^/]+)")

    DEFAULT_MESSAGE = (
        "Sharing illegal content on this server is not permitted and rooms in"
        " violation will be blocked."
    )

    def __init__(self, hs):
        self.hs = hs
        self.store = hs.get_datastore()
        self.state = hs.get_state_handler()
        self._room_creation_handler = hs.get_room_creation_handler()
        self.event_creation_handler = hs.get_event_creation_handler()
        self.room_member_handler = hs.get_room_member_handler()
        self.auth = hs.get_auth()

    @defer.inlineCallbacks
    def on_POST(self, request, room_id):
        requester = yield self.auth.get_user_by_req(request)
        yield assert_user_is_admin(self.auth, requester.user)

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

        requester_user_id = requester.user.to_string()

        logger.info(
            "Shutting down room %r, joining to new room: %r",
            room_id, new_room_id,
        )

        # This will work even if the room is already blocked, but that is
        # desirable in case the first attempt at blocking the room failed below.
        yield self.store.block_room(room_id, requester_user_id)

        users = yield self.state.get_current_users_in_room(room_id)
        kicked_users = []
        failed_to_kick_users = []
        for user_id in users:
            if not self.hs.is_mine_id(user_id):
                continue

            logger.info("Kicking %r from %r...", user_id, room_id)

            try:
                target_requester = create_requester(user_id)
                yield self.room_member_handler.update_membership(
                    requester=target_requester,
                    target=target_requester.user,
                    room_id=room_id,
                    action=Membership.LEAVE,
                    content={},
                    ratelimit=False,
                    require_consent=False,
                )

                yield self.room_member_handler.forget(target_requester.user, room_id)

                yield self.room_member_handler.update_membership(
                    requester=target_requester,
                    target=target_requester.user,
                    room_id=new_room_id,
                    action=Membership.JOIN,
                    content={},
                    ratelimit=False,
                    require_consent=False,
                )

                kicked_users.append(user_id)
            except Exception:
                logger.exception(
                    "Failed to leave old room and join new room for %r", user_id,
                )
                failed_to_kick_users.append(user_id)

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

        aliases_for_room = yield self.store.get_aliases_for_room(room_id)

        yield self.store.update_aliases_for_room(
            room_id, new_room_id, requester_user_id
        )

        defer.returnValue((200, {
            "kicked_users": kicked_users,
            "failed_to_kick_users": failed_to_kick_users,
            "local_aliases": aliases_for_room,
            "new_room_id": new_room_id,
        }))


class QuarantineMediaInRoom(RestServlet):
    """Quarantines all media in a room so that no one can download it via
    this server.
    """
    PATTERNS = historical_admin_path_patterns("/quarantine_media/(?P<room_id>[^/]+)")

    def __init__(self, hs):
        self.store = hs.get_datastore()
        self.auth = hs.get_auth()

    @defer.inlineCallbacks
    def on_POST(self, request, room_id):
        requester = yield self.auth.get_user_by_req(request)
        yield assert_user_is_admin(self.auth, requester.user)

        num_quarantined = yield self.store.quarantine_media_ids_in_room(
            room_id, requester.user.to_string(),
        )

        defer.returnValue((200, {"num_quarantined": num_quarantined}))


class ListMediaInRoom(RestServlet):
    """Lists all of the media in a given room.
    """
    PATTERNS = historical_admin_path_patterns("/room/(?P<room_id>[^/]+)/media")

    def __init__(self, hs):
        self.store = hs.get_datastore()

    @defer.inlineCallbacks
    def on_GET(self, request, room_id):
        requester = yield self.auth.get_user_by_req(request)
        is_admin = yield self.auth.is_server_admin(requester.user)
        if not is_admin:
            raise AuthError(403, "You are not a server admin")

        local_mxcs, remote_mxcs = yield self.store.get_media_mxcs_in_room(room_id)

        defer.returnValue((200, {"local": local_mxcs, "remote": remote_mxcs}))


class ResetPasswordRestServlet(RestServlet):
    """Post request to allow an administrator reset password for a user.
    This needs user to have administrator access in Synapse.
        Example:
            http://localhost:8008/_synapse/admin/v1/reset_password/
            @user:to_reset_password?access_token=admin_access_token
        JsonBodyToSend:
            {
                "new_password": "secret"
            }
        Returns:
            200 OK with empty object if success otherwise an error.
        """
    PATTERNS = historical_admin_path_patterns("/reset_password/(?P<target_user_id>[^/]*)")

    def __init__(self, hs):
        self.store = hs.get_datastore()
        self.hs = hs
        self.auth = hs.get_auth()
        self._set_password_handler = hs.get_set_password_handler()

    @defer.inlineCallbacks
    def on_POST(self, request, target_user_id):
        """Post request to allow an administrator reset password for a user.
        This needs user to have administrator access in Synapse.
        """
        requester = yield self.auth.get_user_by_req(request)
        yield assert_user_is_admin(self.auth, requester.user)

        UserID.from_string(target_user_id)

        params = parse_json_object_from_request(request)
        assert_params_in_dict(params, ["new_password"])
        new_password = params['new_password']

        yield self._set_password_handler.set_password(
            target_user_id, new_password, requester
        )
        defer.returnValue((200, {}))


class GetUsersPaginatedRestServlet(RestServlet):
    """Get request to get specific number of users from Synapse.
    This needs user to have administrator access in Synapse.
        Example:
            http://localhost:8008/_synapse/admin/v1/users_paginate/
            @admin:user?access_token=admin_access_token&start=0&limit=10
        Returns:
            200 OK with json object {list[dict[str, Any]], count} or empty object.
        """
    PATTERNS = historical_admin_path_patterns("/users_paginate/(?P<target_user_id>[^/]*)")

    def __init__(self, hs):
        self.store = hs.get_datastore()
        self.hs = hs
        self.auth = hs.get_auth()
        self.handlers = hs.get_handlers()

    @defer.inlineCallbacks
    def on_GET(self, request, target_user_id):
        """Get request to get specific number of users from Synapse.
        This needs user to have administrator access in Synapse.
        """
        yield assert_requester_is_admin(self.auth, request)

        target_user = UserID.from_string(target_user_id)

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
            http://localhost:8008/_synapse/admin/v1/users_paginate/
            @admin:user?access_token=admin_access_token
        JsonBodyToSend:
            {
                "start": "0",
                "limit": "10
            }
        Returns:
            200 OK with json object {list[dict[str, Any]], count} or empty object.
        """
        yield assert_requester_is_admin(self.auth, request)
        UserID.from_string(target_user_id)

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


class SearchUsersRestServlet(RestServlet):
    """Get request to search user table for specific users according to
    search term.
    This needs user to have administrator access in Synapse.
        Example:
            http://localhost:8008/_synapse/admin/v1/search_users/
            @admin:user?access_token=admin_access_token&term=alice
        Returns:
            200 OK with json object {list[dict[str, Any]], count} or empty object.
    """
    PATTERNS = historical_admin_path_patterns("/search_users/(?P<target_user_id>[^/]*)")

    def __init__(self, hs):
        self.store = hs.get_datastore()
        self.hs = hs
        self.auth = hs.get_auth()
        self.handlers = hs.get_handlers()

    @defer.inlineCallbacks
    def on_GET(self, request, target_user_id):
        """Get request to search user table for specific users according to
        search term.
        This needs user to have a administrator access in Synapse.
        """
        yield assert_requester_is_admin(self.auth, request)

        target_user = UserID.from_string(target_user_id)

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


class DeleteGroupAdminRestServlet(RestServlet):
    """Allows deleting of local groups
    """
    PATTERNS = historical_admin_path_patterns("/delete_group/(?P<group_id>[^/]*)")

    def __init__(self, hs):
        self.group_server = hs.get_groups_server_handler()
        self.is_mine_id = hs.is_mine_id
        self.auth = hs.get_auth()

    @defer.inlineCallbacks
    def on_POST(self, request, group_id):
        requester = yield self.auth.get_user_by_req(request)
        yield assert_user_is_admin(self.auth, requester.user)

        if not self.is_mine_id(group_id):
            raise SynapseError(400, "Can only delete local groups")

        yield self.group_server.delete_group(group_id, requester.user.to_string())
        defer.returnValue((200, {}))


class AccountValidityRenewServlet(RestServlet):
    PATTERNS = historical_admin_path_patterns("/account_validity/validity$")

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        self.hs = hs
        self.account_activity_handler = hs.get_account_validity_handler()
        self.auth = hs.get_auth()

    @defer.inlineCallbacks
    def on_POST(self, request):
        yield assert_requester_is_admin(self.auth, request)

        body = parse_json_object_from_request(request)

        if "user_id" not in body:
            raise SynapseError(400, "Missing property 'user_id' in the request body")

        expiration_ts = yield self.account_activity_handler.renew_account_for_user(
            body["user_id"], body.get("expiration_ts"),
            not body.get("enable_renewal_emails", True),
        )

        res = {
            "expiration_ts": expiration_ts,
        }
        defer.returnValue((200, res))

########################################################################################
#
# please don't add more servlets here: this file is already long and unwieldy. Put
# them in separate files within the 'admin' package.
#
########################################################################################


class AdminRestResource(JsonResource):
    """The REST resource which gets mounted at /_synapse/admin"""

    def __init__(self, hs):
        JsonResource.__init__(self, hs, canonical_json=False)

        register_servlets_for_client_rest_resource(hs, self)
        SendServerNoticeServlet(hs).register(self)
        VersionServlet(hs).register(self)


def register_servlets_for_client_rest_resource(hs, http_server):
    """Register only the servlets which need to be exposed on /_matrix/client/xxx"""
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
    DeleteGroupAdminRestServlet(hs).register(http_server)
    AccountValidityRenewServlet(hs).register(http_server)
    # don't add more things here: new servlets should only be exposed on
    # /_synapse/admin so should not go here. Instead register them in AdminRestResource.
