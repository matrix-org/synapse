# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.
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
from http import HTTPStatus
from typing import TYPE_CHECKING, Tuple

from synapse.api.constants import UserTypes
from synapse.api.errors import Codes, NotFoundError, SynapseError
from synapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_boolean,
    parse_integer,
    parse_json_object_from_request,
    parse_string,
)
from synapse.http.site import SynapseRequest
from synapse.rest.admin._base import (
    admin_patterns,
    assert_requester_is_admin,
    assert_user_is_admin,
)
from synapse.rest.client.v2_alpha._base import client_patterns
from synapse.types import JsonDict, UserID

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class UsersRestServlet(RestServlet):
    PATTERNS = admin_patterns("/users/(?P<user_id>[^/]*)$")

    def __init__(self, hs):
        self.hs = hs
        self.store = hs.get_datastore()
        self.auth = hs.get_auth()
        self.admin_handler = hs.get_admin_handler()

    async def on_GET(self, request, user_id):
        target_user = UserID.from_string(user_id)
        await assert_requester_is_admin(self.auth, request)

        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "Can only users a local user")

        ret = await self.store.get_users()

        return 200, ret


class UsersRestServletV2(RestServlet):
    PATTERNS = admin_patterns("/users$", "v2")

    """Get request to list all local users.
    This needs user to have administrator access in Synapse.

    GET /_synapse/admin/v2/users?from=0&limit=10&guests=false

    returns:
        200 OK with list of users if success otherwise an error.

    The parameters `from` and `limit` are required only for pagination.
    By default, a `limit` of 100 is used.
    The parameter `user_id` can be used to filter by user id.
    The parameter `name` can be used to filter by user id or display name.
    The parameter `guests` can be used to exclude guest users.
    The parameter `deactivated` can be used to include deactivated users.
    """

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.store = hs.get_datastore()
        self.auth = hs.get_auth()
        self.admin_handler = hs.get_admin_handler()

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        start = parse_integer(request, "from", default=0)
        limit = parse_integer(request, "limit", default=100)

        if start < 0:
            raise SynapseError(
                400,
                "Query parameter from must be a string representing a positive integer.",
                errcode=Codes.INVALID_PARAM,
            )

        if limit < 0:
            raise SynapseError(
                400,
                "Query parameter limit must be a string representing a positive integer.",
                errcode=Codes.INVALID_PARAM,
            )

        user_id = parse_string(request, "user_id", default=None)
        name = parse_string(request, "name", default=None)
        guests = parse_boolean(request, "guests", default=True)
        deactivated = parse_boolean(request, "deactivated", default=False)

        users, total = await self.store.get_users_paginate(
            start, limit, user_id, name, guests, deactivated
        )
        ret = {"users": users, "total": total}
        if (start + limit) < total:
            ret["next_token"] = str(start + len(users))

        return 200, ret


class UserRestServletV2(RestServlet):
    PATTERNS = admin_patterns("/users/(?P<user_id>[^/]+)$", "v2")

    """Get request to list user details.
    This needs user to have administrator access in Synapse.

    GET /_synapse/admin/v2/users/<user_id>

    returns:
        200 OK with user details if success otherwise an error.

    Put request to allow an administrator to add or modify a user.
    This needs user to have administrator access in Synapse.
    We use PUT instead of POST since we already know the id of the user
    object to create. POST could be used to create guests.

    PUT /_synapse/admin/v2/users/<user_id>
    {
        "password": "secret",
        "displayname": "User"
    }

    returns:
        201 OK with new user object if user was created or
        200 OK with modified user object if user was modified
        otherwise an error.
    """

    def __init__(self, hs):
        self.hs = hs
        self.auth = hs.get_auth()
        self.admin_handler = hs.get_admin_handler()
        self.store = hs.get_datastore()
        self.auth_handler = hs.get_auth_handler()
        self.profile_handler = hs.get_profile_handler()
        self.set_password_handler = hs.get_set_password_handler()
        self.deactivate_account_handler = hs.get_deactivate_account_handler()
        self.registration_handler = hs.get_registration_handler()
        self.pusher_pool = hs.get_pusherpool()

    async def on_GET(self, request, user_id):
        await assert_requester_is_admin(self.auth, request)

        target_user = UserID.from_string(user_id)
        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "Can only lookup local users")

        ret = await self.admin_handler.get_user(target_user)

        if not ret:
            raise NotFoundError("User not found")

        return 200, ret

    async def on_PUT(self, request, user_id):
        requester = await self.auth.get_user_by_req(request)
        await assert_user_is_admin(self.auth, requester.user)

        target_user = UserID.from_string(user_id)
        body = parse_json_object_from_request(request)

        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "This endpoint can only be used with local users")

        user = await self.admin_handler.get_user(target_user)
        user_id = target_user.to_string()

        if user:  # modify user
            if "displayname" in body:
                await self.profile_handler.set_displayname(
                    target_user, requester, body["displayname"], True
                )

            if "threepids" in body:
                # check for required parameters for each threepid
                for threepid in body["threepids"]:
                    assert_params_in_dict(threepid, ["medium", "address"])

                # remove old threepids from user
                threepids = await self.store.user_get_threepids(user_id)
                for threepid in threepids:
                    try:
                        await self.auth_handler.delete_threepid(
                            user_id, threepid["medium"], threepid["address"], None
                        )
                    except Exception:
                        logger.exception("Failed to remove threepids")
                        raise SynapseError(500, "Failed to remove threepids")

                # add new threepids to user
                current_time = self.hs.get_clock().time_msec()
                for threepid in body["threepids"]:
                    await self.auth_handler.add_threepid(
                        user_id, threepid["medium"], threepid["address"], current_time
                    )

            if "avatar_url" in body and type(body["avatar_url"]) == str:
                await self.profile_handler.set_avatar_url(
                    target_user, requester, body["avatar_url"], True
                )

            if "admin" in body:
                set_admin_to = bool(body["admin"])
                if set_admin_to != user["admin"]:
                    auth_user = requester.user
                    if target_user == auth_user and not set_admin_to:
                        raise SynapseError(400, "You may not demote yourself.")

                    await self.store.set_server_admin(target_user, set_admin_to)

            if "password" in body:
                if not isinstance(body["password"], str) or len(body["password"]) > 512:
                    raise SynapseError(400, "Invalid password")
                else:
                    new_password = body["password"]
                    logout_devices = True

                    new_password_hash = await self.auth_handler.hash(new_password)

                    await self.set_password_handler.set_password(
                        target_user.to_string(),
                        new_password_hash,
                        logout_devices,
                        requester,
                    )

            if "deactivated" in body:
                deactivate = body["deactivated"]
                if not isinstance(deactivate, bool):
                    raise SynapseError(
                        400, "'deactivated' parameter is not of type boolean"
                    )

                if deactivate and not user["deactivated"]:
                    await self.deactivate_account_handler.deactivate_account(
                        target_user.to_string(), False, requester, by_admin=True
                    )
                elif not deactivate and user["deactivated"]:
                    if "password" not in body:
                        raise SynapseError(
                            400, "Must provide a password to re-activate an account."
                        )

                    await self.deactivate_account_handler.activate_account(
                        target_user.to_string()
                    )

            user = await self.admin_handler.get_user(target_user)
            return 200, user

        else:  # create user
            password = body.get("password")
            password_hash = None
            if password is not None:
                if not isinstance(password, str) or len(password) > 512:
                    raise SynapseError(400, "Invalid password")
                password_hash = await self.auth_handler.hash(password)

            admin = body.get("admin", None)
            user_type = body.get("user_type", None)
            displayname = body.get("displayname", None)

            if user_type is not None and user_type not in UserTypes.ALL_USER_TYPES:
                raise SynapseError(400, "Invalid user type")

            user_id = await self.registration_handler.register_user(
                localpart=target_user.localpart,
                password_hash=password_hash,
                admin=bool(admin),
                default_display_name=displayname,
                user_type=user_type,
                by_admin=True,
            )

            if "threepids" in body:
                # check for required parameters for each threepid
                for threepid in body["threepids"]:
                    assert_params_in_dict(threepid, ["medium", "address"])

                current_time = self.hs.get_clock().time_msec()
                for threepid in body["threepids"]:
                    await self.auth_handler.add_threepid(
                        user_id, threepid["medium"], threepid["address"], current_time
                    )
                    if (
                        self.hs.config.email_enable_notifs
                        and self.hs.config.email_notif_for_new_users
                    ):
                        await self.pusher_pool.add_pusher(
                            user_id=user_id,
                            access_token=None,
                            kind="email",
                            app_id="m.email",
                            app_display_name="Email Notifications",
                            device_display_name=threepid["address"],
                            pushkey=threepid["address"],
                            lang=None,  # We don't know a user's language here
                            data={},
                        )

            if "avatar_url" in body and isinstance(body["avatar_url"], str):
                await self.profile_handler.set_avatar_url(
                    target_user, requester, body["avatar_url"], True
                )

            ret = await self.admin_handler.get_user(target_user)

            return 201, ret


class UserRegisterServlet(RestServlet):
    """
    Attributes:
         NONCE_TIMEOUT (int): Seconds until a generated nonce won't be accepted
         nonces (dict[str, int]): The nonces that we will accept. A dict of
             nonce to the time it was generated, in int seconds.
    """

    PATTERNS = admin_patterns("/register")
    NONCE_TIMEOUT = 60

    def __init__(self, hs):
        self.auth_handler = hs.get_auth_handler()
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
        return 200, {"nonce": nonce}

    async def on_POST(self, request):
        self._clear_old_nonces()

        if not self.hs.config.registration_shared_secret:
            raise SynapseError(400, "Shared secret registration is not enabled")

        body = parse_json_object_from_request(request)

        if "nonce" not in body:
            raise SynapseError(400, "nonce must be specified", errcode=Codes.BAD_JSON)

        nonce = body["nonce"]

        if nonce not in self.nonces:
            raise SynapseError(400, "unrecognised nonce")

        # Delete the nonce, so it can't be reused, even if it's invalid
        del self.nonces[nonce]

        if "username" not in body:
            raise SynapseError(
                400, "username must be specified", errcode=Codes.BAD_JSON
            )
        else:
            if not isinstance(body["username"], str) or len(body["username"]) > 512:
                raise SynapseError(400, "Invalid username")

            username = body["username"].encode("utf-8")
            if b"\x00" in username:
                raise SynapseError(400, "Invalid username")

        if "password" not in body:
            raise SynapseError(
                400, "password must be specified", errcode=Codes.BAD_JSON
            )
        else:
            password = body["password"]
            if not isinstance(password, str) or len(password) > 512:
                raise SynapseError(400, "Invalid password")

            password_bytes = password.encode("utf-8")
            if b"\x00" in password_bytes:
                raise SynapseError(400, "Invalid password")

            password_hash = await self.auth_handler.hash(password)

        admin = body.get("admin", None)
        user_type = body.get("user_type", None)
        displayname = body.get("displayname", None)

        if user_type is not None and user_type not in UserTypes.ALL_USER_TYPES:
            raise SynapseError(400, "Invalid user type")

        if "mac" not in body:
            raise SynapseError(400, "mac must be specified", errcode=Codes.BAD_JSON)

        got_mac = body["mac"]

        want_mac_builder = hmac.new(
            key=self.hs.config.registration_shared_secret.encode(),
            digestmod=hashlib.sha1,
        )
        want_mac_builder.update(nonce.encode("utf8"))
        want_mac_builder.update(b"\x00")
        want_mac_builder.update(username)
        want_mac_builder.update(b"\x00")
        want_mac_builder.update(password_bytes)
        want_mac_builder.update(b"\x00")
        want_mac_builder.update(b"admin" if admin else b"notadmin")
        if user_type:
            want_mac_builder.update(b"\x00")
            want_mac_builder.update(user_type.encode("utf8"))

        want_mac = want_mac_builder.hexdigest()

        if not hmac.compare_digest(want_mac.encode("ascii"), got_mac.encode("ascii")):
            raise SynapseError(403, "HMAC incorrect")

        # Reuse the parts of RegisterRestServlet to reduce code duplication
        from synapse.rest.client.v2_alpha.register import RegisterRestServlet

        register = RegisterRestServlet(self.hs)

        user_id = await register.registration_handler.register_user(
            localpart=body["username"].lower(),
            password_hash=password_hash,
            admin=bool(admin),
            user_type=user_type,
            default_display_name=displayname,
            by_admin=True,
        )

        result = await register._create_registration_details(user_id, body)
        return 200, result


class WhoisRestServlet(RestServlet):
    path_regex = "/whois/(?P<user_id>[^/]*)$"
    PATTERNS = (
        admin_patterns(path_regex)
        +
        # URL for spec reason
        # https://matrix.org/docs/spec/client_server/r0.6.1#get-matrix-client-r0-admin-whois-userid
        client_patterns("/admin" + path_regex, v1=True)
    )

    def __init__(self, hs):
        self.hs = hs
        self.auth = hs.get_auth()
        self.admin_handler = hs.get_admin_handler()

    async def on_GET(self, request, user_id):
        target_user = UserID.from_string(user_id)
        requester = await self.auth.get_user_by_req(request)
        auth_user = requester.user

        if target_user != auth_user:
            await assert_user_is_admin(self.auth, auth_user)

        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "Can only whois a local user")

        ret = await self.admin_handler.get_whois(target_user)

        return 200, ret


class DeactivateAccountRestServlet(RestServlet):
    PATTERNS = admin_patterns("/deactivate/(?P<target_user_id>[^/]*)")

    def __init__(self, hs: "HomeServer"):
        self._deactivate_account_handler = hs.get_deactivate_account_handler()
        self.auth = hs.get_auth()
        self.is_mine = hs.is_mine
        self.store = hs.get_datastore()

    async def on_POST(self, request: str, target_user_id: str) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        await assert_user_is_admin(self.auth, requester.user)

        if not self.is_mine(UserID.from_string(target_user_id)):
            raise SynapseError(400, "Can only deactivate local users")

        if not await self.store.get_user_by_id(target_user_id):
            raise NotFoundError("User not found")

        body = parse_json_object_from_request(request, allow_empty_body=True)
        erase = body.get("erase", False)
        if not isinstance(erase, bool):
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "Param 'erase' must be a boolean, if given",
                Codes.BAD_JSON,
            )

        result = await self._deactivate_account_handler.deactivate_account(
            target_user_id, erase, requester, by_admin=True
        )
        if result:
            id_server_unbind_result = "success"
        else:
            id_server_unbind_result = "no-support"

        return 200, {"id_server_unbind_result": id_server_unbind_result}


class AccountValidityRenewServlet(RestServlet):
    PATTERNS = admin_patterns("/account_validity/validity$")

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        self.hs = hs
        self.account_activity_handler = hs.get_account_validity_handler()
        self.auth = hs.get_auth()

    async def on_POST(self, request):
        await assert_requester_is_admin(self.auth, request)

        body = parse_json_object_from_request(request)

        if "user_id" not in body:
            raise SynapseError(400, "Missing property 'user_id' in the request body")

        expiration_ts = await self.account_activity_handler.renew_account_for_user(
            body["user_id"],
            body.get("expiration_ts"),
            not body.get("enable_renewal_emails", True),
        )

        res = {"expiration_ts": expiration_ts}
        return 200, res


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

    PATTERNS = admin_patterns("/reset_password/(?P<target_user_id>[^/]*)")

    def __init__(self, hs):
        self.store = hs.get_datastore()
        self.hs = hs
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_auth_handler()
        self._set_password_handler = hs.get_set_password_handler()

    async def on_POST(self, request, target_user_id):
        """Post request to allow an administrator reset password for a user.
        This needs user to have administrator access in Synapse.
        """
        requester = await self.auth.get_user_by_req(request)
        await assert_user_is_admin(self.auth, requester.user)

        UserID.from_string(target_user_id)

        params = parse_json_object_from_request(request)
        assert_params_in_dict(params, ["new_password"])
        new_password = params["new_password"]
        logout_devices = params.get("logout_devices", True)

        new_password_hash = await self.auth_handler.hash(new_password)

        await self._set_password_handler.set_password(
            target_user_id, new_password_hash, logout_devices, requester
        )
        return 200, {}


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

    PATTERNS = admin_patterns("/search_users/(?P<target_user_id>[^/]*)")

    def __init__(self, hs):
        self.hs = hs
        self.store = hs.get_datastore()
        self.auth = hs.get_auth()

    async def on_GET(self, request, target_user_id):
        """Get request to search user table for specific users according to
        search term.
        This needs user to have a administrator access in Synapse.
        """
        await assert_requester_is_admin(self.auth, request)

        target_user = UserID.from_string(target_user_id)

        # To allow all users to get the users list
        # if not is_admin and target_user != auth_user:
        #     raise AuthError(403, "You are not a server admin")

        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "Can only users a local user")

        term = parse_string(request, "term", required=True)
        logger.info("term: %s ", term)

        ret = await self.store.search_users(term)
        return 200, ret


class UserAdminServlet(RestServlet):
    """
    Get or set whether or not a user is a server administrator.

    Note that only local users can be server administrators, and that an
    administrator may not demote themselves.

    Only server administrators can use this API.

    Examples:
        * Get
            GET /_synapse/admin/v1/users/@nonadmin:example.com/admin
            response on success:
                {
                    "admin": false
                }
        * Set
            PUT /_synapse/admin/v1/users/@reivilibre:librepush.net/admin
            request body:
                {
                    "admin": true
                }
            response on success:
                {}
    """

    PATTERNS = admin_patterns("/users/(?P<user_id>[^/]*)/admin$")

    def __init__(self, hs):
        self.hs = hs
        self.store = hs.get_datastore()
        self.auth = hs.get_auth()

    async def on_GET(self, request, user_id):
        await assert_requester_is_admin(self.auth, request)

        target_user = UserID.from_string(user_id)

        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "Only local users can be admins of this homeserver")

        is_admin = await self.store.is_server_admin(target_user)

        return 200, {"admin": is_admin}

    async def on_PUT(self, request, user_id):
        requester = await self.auth.get_user_by_req(request)
        await assert_user_is_admin(self.auth, requester.user)
        auth_user = requester.user

        target_user = UserID.from_string(user_id)

        body = parse_json_object_from_request(request)

        assert_params_in_dict(body, ["admin"])

        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "Only local users can be admins of this homeserver")

        set_admin_to = bool(body["admin"])

        if target_user == auth_user and not set_admin_to:
            raise SynapseError(400, "You may not demote yourself.")

        await self.store.set_server_admin(target_user, set_admin_to)

        return 200, {}


class UserMembershipRestServlet(RestServlet):
    """
    Get room list of an user.
    """

    PATTERNS = admin_patterns("/users/(?P<user_id>[^/]+)/joined_rooms$")

    def __init__(self, hs):
        self.is_mine = hs.is_mine
        self.auth = hs.get_auth()
        self.store = hs.get_datastore()

    async def on_GET(self, request, user_id):
        await assert_requester_is_admin(self.auth, request)

        room_ids = await self.store.get_rooms_for_user(user_id)
        ret = {"joined_rooms": list(room_ids), "total": len(room_ids)}
        return 200, ret


class PushersRestServlet(RestServlet):
    """
    Gets information about all pushers for a specific `user_id`.

    Example:
        http://localhost:8008/_synapse/admin/v1/users/
        @user:server/pushers

    Returns:
        pushers: Dictionary containing pushers information.
        total: Number of pushers in dictonary `pushers`.
    """

    PATTERNS = admin_patterns("/users/(?P<user_id>[^/]*)/pushers$")

    def __init__(self, hs):
        self.is_mine = hs.is_mine
        self.store = hs.get_datastore()
        self.auth = hs.get_auth()

    async def on_GET(
        self, request: SynapseRequest, user_id: str
    ) -> Tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        if not self.is_mine(UserID.from_string(user_id)):
            raise SynapseError(400, "Can only lookup local users")

        if not await self.store.get_user_by_id(user_id):
            raise NotFoundError("User not found")

        pushers = await self.store.get_pushers_by_user_id(user_id)

        filtered_pushers = [p.as_dict() for p in pushers]

        return 200, {"pushers": filtered_pushers, "total": len(filtered_pushers)}


class UserMediaRestServlet(RestServlet):
    """
    Gets information about all uploaded local media for a specific `user_id`.

    Example:
        http://localhost:8008/_synapse/admin/v1/users/
        @user:server/media

    Args:
        The parameters `from` and `limit` are required for pagination.
        By default, a `limit` of 100 is used.
    Returns:
        A list of media and an integer representing the total number of
        media that exist given for this user
    """

    PATTERNS = admin_patterns("/users/(?P<user_id>[^/]+)/media$")

    def __init__(self, hs):
        self.is_mine = hs.is_mine
        self.auth = hs.get_auth()
        self.store = hs.get_datastore()

    async def on_GET(
        self, request: SynapseRequest, user_id: str
    ) -> Tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        if not self.is_mine(UserID.from_string(user_id)):
            raise SynapseError(400, "Can only lookup local users")

        user = await self.store.get_user_by_id(user_id)
        if user is None:
            raise NotFoundError("Unknown user")

        start = parse_integer(request, "from", default=0)
        limit = parse_integer(request, "limit", default=100)

        if start < 0:
            raise SynapseError(
                400,
                "Query parameter from must be a string representing a positive integer.",
                errcode=Codes.INVALID_PARAM,
            )

        if limit < 0:
            raise SynapseError(
                400,
                "Query parameter limit must be a string representing a positive integer.",
                errcode=Codes.INVALID_PARAM,
            )

        media, total = await self.store.get_local_media_by_user_paginate(
            start, limit, user_id
        )

        ret = {"media": media, "total": total}
        if (start + limit) < total:
            ret["next_token"] = start + len(media)

        return 200, ret


class UserTokenRestServlet(RestServlet):
    """An admin API for logging in as a user.

    Example:

        POST /_synapse/admin/v1/users/@test:example.com/login
        {}

        200 OK
        {
            "access_token": "<some_token>"
        }
    """

    PATTERNS = admin_patterns("/users/(?P<user_id>[^/]*)/login$")

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.store = hs.get_datastore()
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_auth_handler()

    async def on_POST(self, request, user_id):
        requester = await self.auth.get_user_by_req(request)
        await assert_user_is_admin(self.auth, requester.user)
        auth_user = requester.user

        if not self.hs.is_mine_id(user_id):
            raise SynapseError(400, "Only local users can be logged in as")

        body = parse_json_object_from_request(request, allow_empty_body=True)

        valid_until_ms = body.get("valid_until_ms")
        if valid_until_ms and not isinstance(valid_until_ms, int):
            raise SynapseError(400, "'valid_until_ms' parameter must be an int")

        if auth_user.to_string() == user_id:
            raise SynapseError(400, "Cannot use admin API to login as self")

        token = await self.auth_handler.get_access_token_for_user_id(
            user_id=auth_user.to_string(),
            device_id=None,
            valid_until_ms=valid_until_ms,
            puppets_user_id=user_id,
        )

        return 200, {"access_token": token}


class ShadowBanRestServlet(RestServlet):
    """An admin API for shadow-banning a user.

    A shadow-banned users receives successful responses to their client-server
    API requests, but the events are not propagated into rooms.

    Shadow-banning a user should be used as a tool of last resort and may lead
    to confusing or broken behaviour for the client.

    Example:

        POST /_synapse/admin/v1/users/@test:example.com/shadow_ban
        {}

        200 OK
        {}
    """

    PATTERNS = admin_patterns("/users/(?P<user_id>[^/]*)/shadow_ban")

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.store = hs.get_datastore()
        self.auth = hs.get_auth()

    async def on_POST(self, request, user_id):
        await assert_requester_is_admin(self.auth, request)

        if not self.hs.is_mine_id(user_id):
            raise SynapseError(400, "Only local users can be shadow-banned")

        await self.store.set_shadow_banned(UserID.from_string(user_id), True)

        return 200, {}
