# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2017 Vector Creations Ltd
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
import logging

from six.moves import http_client

from twisted.internet import defer

from synapse.api.constants import LoginType
from synapse.api.errors import Codes, SynapseError
from synapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_json_object_from_request,
)
from synapse.util.msisdn import phone_number_to_msisdn
from synapse.util.threepids import check_3pid_allowed

from ._base import client_v2_patterns, interactive_auth_handler

logger = logging.getLogger(__name__)


class EmailPasswordRequestTokenRestServlet(RestServlet):
    PATTERNS = client_v2_patterns("/account/password/email/requestToken$")

    def __init__(self, hs):
        super(EmailPasswordRequestTokenRestServlet, self).__init__()
        self.hs = hs
        self.identity_handler = hs.get_handlers().identity_handler

    @defer.inlineCallbacks
    def on_POST(self, request):
        body = parse_json_object_from_request(request)

        assert_params_in_dict(body, [
            'id_server', 'client_secret', 'email', 'send_attempt'
        ])

        if not check_3pid_allowed(self.hs, "email", body['email']):
            raise SynapseError(
                403,
                "Your email domain is not authorized on this server",
                Codes.THREEPID_DENIED,
            )

        existingUid = yield self.hs.get_datastore().get_user_id_by_threepid(
            'email', body['email']
        )

        if existingUid is None:
            raise SynapseError(400, "Email not found", Codes.THREEPID_NOT_FOUND)

        ret = yield self.identity_handler.requestEmailToken(**body)
        defer.returnValue((200, ret))


class MsisdnPasswordRequestTokenRestServlet(RestServlet):
    PATTERNS = client_v2_patterns("/account/password/msisdn/requestToken$")

    def __init__(self, hs):
        super(MsisdnPasswordRequestTokenRestServlet, self).__init__()
        self.hs = hs
        self.datastore = self.hs.get_datastore()
        self.identity_handler = hs.get_handlers().identity_handler

    @defer.inlineCallbacks
    def on_POST(self, request):
        body = parse_json_object_from_request(request)

        assert_params_in_dict(body, [
            'id_server', 'client_secret',
            'country', 'phone_number', 'send_attempt',
        ])

        msisdn = phone_number_to_msisdn(body['country'], body['phone_number'])

        if not check_3pid_allowed(self.hs, "msisdn", msisdn):
            raise SynapseError(
                403,
                "Account phone numbers are not authorized on this server",
                Codes.THREEPID_DENIED,
            )

        existingUid = yield self.datastore.get_user_id_by_threepid(
            'msisdn', msisdn
        )

        if existingUid is None:
            raise SynapseError(400, "MSISDN not found", Codes.THREEPID_NOT_FOUND)

        ret = yield self.identity_handler.requestMsisdnToken(**body)
        defer.returnValue((200, ret))


class PasswordRestServlet(RestServlet):
    PATTERNS = client_v2_patterns("/account/password$")

    def __init__(self, hs):
        super(PasswordRestServlet, self).__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_auth_handler()
        self.datastore = self.hs.get_datastore()
        self._set_password_handler = hs.get_set_password_handler()

    @interactive_auth_handler
    @defer.inlineCallbacks
    def on_POST(self, request):
        body = parse_json_object_from_request(request)

        # there are two possibilities here. Either the user does not have an
        # access token, and needs to do a password reset; or they have one and
        # need to validate their identity.
        #
        # In the first case, we offer a couple of means of identifying
        # themselves (email and msisdn, though it's unclear if msisdn actually
        # works).
        #
        # In the second case, we require a password to confirm their identity.

        if self.auth.has_access_token(request):
            requester = yield self.auth.get_user_by_req(request)
            params = yield self.auth_handler.validate_user_via_ui_auth(
                requester, body, self.hs.get_ip_from_request(request),
            )
            user_id = requester.user.to_string()
        else:
            requester = None
            result, params, _ = yield self.auth_handler.check_auth(
                [[LoginType.EMAIL_IDENTITY], [LoginType.MSISDN]],
                body, self.hs.get_ip_from_request(request),
            )

            if LoginType.EMAIL_IDENTITY in result:
                threepid = result[LoginType.EMAIL_IDENTITY]
                if 'medium' not in threepid or 'address' not in threepid:
                    raise SynapseError(500, "Malformed threepid")
                if threepid['medium'] == 'email':
                    # For emails, transform the address to lowercase.
                    # We store all email addreses as lowercase in the DB.
                    # (See add_threepid in synapse/handlers/auth.py)
                    threepid['address'] = threepid['address'].lower()
                # if using email, we must know about the email they're authing with!
                threepid_user_id = yield self.datastore.get_user_id_by_threepid(
                    threepid['medium'], threepid['address']
                )
                if not threepid_user_id:
                    raise SynapseError(404, "Email address not found", Codes.NOT_FOUND)
                user_id = threepid_user_id
            else:
                logger.error("Auth succeeded but no known type! %r", result.keys())
                raise SynapseError(500, "", Codes.UNKNOWN)

        assert_params_in_dict(params, ["new_password"])
        new_password = params['new_password']

        yield self._set_password_handler.set_password(
            user_id, new_password, requester
        )

        defer.returnValue((200, {}))

    def on_OPTIONS(self, _):
        return 200, {}


class DeactivateAccountRestServlet(RestServlet):
    PATTERNS = client_v2_patterns("/account/deactivate$")

    def __init__(self, hs):
        super(DeactivateAccountRestServlet, self).__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_auth_handler()
        self._deactivate_account_handler = hs.get_deactivate_account_handler()

    @interactive_auth_handler
    @defer.inlineCallbacks
    def on_POST(self, request):
        body = parse_json_object_from_request(request)
        erase = body.get("erase", False)
        if not isinstance(erase, bool):
            raise SynapseError(
                http_client.BAD_REQUEST,
                "Param 'erase' must be a boolean, if given",
                Codes.BAD_JSON,
            )

        requester = yield self.auth.get_user_by_req(request)

        # allow ASes to dectivate their own users
        if requester.app_service:
            yield self._deactivate_account_handler.deactivate_account(
                requester.user.to_string(), erase,
            )
            defer.returnValue((200, {}))

        yield self.auth_handler.validate_user_via_ui_auth(
            requester, body, self.hs.get_ip_from_request(request),
        )
        result = yield self._deactivate_account_handler.deactivate_account(
            requester.user.to_string(), erase,
            id_server=body.get("id_server"),
        )
        if result:
            id_server_unbind_result = "success"
        else:
            id_server_unbind_result = "no-support"

        defer.returnValue((200, {
            "id_server_unbind_result": id_server_unbind_result,
        }))


class EmailThreepidRequestTokenRestServlet(RestServlet):
    PATTERNS = client_v2_patterns("/account/3pid/email/requestToken$")

    def __init__(self, hs):
        self.hs = hs
        super(EmailThreepidRequestTokenRestServlet, self).__init__()
        self.identity_handler = hs.get_handlers().identity_handler
        self.datastore = self.hs.get_datastore()

    @defer.inlineCallbacks
    def on_POST(self, request):
        body = parse_json_object_from_request(request)
        assert_params_in_dict(
            body,
            ['id_server', 'client_secret', 'email', 'send_attempt'],
        )

        if not check_3pid_allowed(self.hs, "email", body['email']):
            raise SynapseError(
                403,
                "Your email domain is not authorized on this server",
                Codes.THREEPID_DENIED,
            )

        existingUid = yield self.datastore.get_user_id_by_threepid(
            'email', body['email']
        )

        if existingUid is not None:
            raise SynapseError(400, "Email is already in use", Codes.THREEPID_IN_USE)

        ret = yield self.identity_handler.requestEmailToken(**body)
        defer.returnValue((200, ret))


class MsisdnThreepidRequestTokenRestServlet(RestServlet):
    PATTERNS = client_v2_patterns("/account/3pid/msisdn/requestToken$")

    def __init__(self, hs):
        self.hs = hs
        super(MsisdnThreepidRequestTokenRestServlet, self).__init__()
        self.identity_handler = hs.get_handlers().identity_handler
        self.datastore = self.hs.get_datastore()

    @defer.inlineCallbacks
    def on_POST(self, request):
        body = parse_json_object_from_request(request)
        assert_params_in_dict(body, [
            'id_server', 'client_secret',
            'country', 'phone_number', 'send_attempt',
        ])

        msisdn = phone_number_to_msisdn(body['country'], body['phone_number'])

        if not check_3pid_allowed(self.hs, "msisdn", msisdn):
            raise SynapseError(
                403,
                "Account phone numbers are not authorized on this server",
                Codes.THREEPID_DENIED,
            )

        existingUid = yield self.datastore.get_user_id_by_threepid(
            'msisdn', msisdn
        )

        if existingUid is not None:
            raise SynapseError(400, "MSISDN is already in use", Codes.THREEPID_IN_USE)

        ret = yield self.identity_handler.requestMsisdnToken(**body)
        defer.returnValue((200, ret))


class ThreepidRestServlet(RestServlet):
    PATTERNS = client_v2_patterns("/account/3pid$")

    def __init__(self, hs):
        super(ThreepidRestServlet, self).__init__()
        self.hs = hs
        self.identity_handler = hs.get_handlers().identity_handler
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_auth_handler()
        self.datastore = self.hs.get_datastore()

    @defer.inlineCallbacks
    def on_GET(self, request):
        requester = yield self.auth.get_user_by_req(request)

        threepids = yield self.datastore.user_get_threepids(
            requester.user.to_string()
        )

        defer.returnValue((200, {'threepids': threepids}))

    @defer.inlineCallbacks
    def on_POST(self, request):
        body = parse_json_object_from_request(request)

        threePidCreds = body.get('threePidCreds')
        threePidCreds = body.get('three_pid_creds', threePidCreds)
        if threePidCreds is None:
            raise SynapseError(400, "Missing param", Codes.MISSING_PARAM)

        requester = yield self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        threepid = yield self.identity_handler.threepid_from_creds(threePidCreds)

        if not threepid:
            raise SynapseError(
                400, "Failed to auth 3pid", Codes.THREEPID_AUTH_FAILED
            )

        for reqd in ['medium', 'address', 'validated_at']:
            if reqd not in threepid:
                logger.warn("Couldn't add 3pid: invalid response from ID server")
                raise SynapseError(500, "Invalid response from ID Server")

        yield self.auth_handler.add_threepid(
            user_id,
            threepid['medium'],
            threepid['address'],
            threepid['validated_at'],
        )

        if 'bind' in body and body['bind']:
            logger.debug(
                "Binding threepid %s to %s",
                threepid, user_id
            )
            yield self.identity_handler.bind_threepid(
                threePidCreds, user_id
            )

        defer.returnValue((200, {}))


class ThreepidDeleteRestServlet(RestServlet):
    PATTERNS = client_v2_patterns("/account/3pid/delete$")

    def __init__(self, hs):
        super(ThreepidDeleteRestServlet, self).__init__()
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_auth_handler()

    @defer.inlineCallbacks
    def on_POST(self, request):
        body = parse_json_object_from_request(request)
        assert_params_in_dict(body, ['medium', 'address'])

        requester = yield self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        try:
            ret = yield self.auth_handler.delete_threepid(
                user_id, body['medium'], body['address'], body.get("id_server"),
            )
        except Exception:
            # NB. This endpoint should succeed if there is nothing to
            # delete, so it should only throw if something is wrong
            # that we ought to care about.
            logger.exception("Failed to remove threepid")
            raise SynapseError(500, "Failed to remove threepid")

        if ret:
            id_server_unbind_result = "success"
        else:
            id_server_unbind_result = "no-support"

        defer.returnValue((200, {
            "id_server_unbind_result": id_server_unbind_result,
        }))


class WhoamiRestServlet(RestServlet):
    PATTERNS = client_v2_patterns("/account/whoami$")

    def __init__(self, hs):
        super(WhoamiRestServlet, self).__init__()
        self.auth = hs.get_auth()

    @defer.inlineCallbacks
    def on_GET(self, request):
        requester = yield self.auth.get_user_by_req(request)

        defer.returnValue((200, {'user_id': requester.user.to_string()}))


def register_servlets(hs, http_server):
    EmailPasswordRequestTokenRestServlet(hs).register(http_server)
    MsisdnPasswordRequestTokenRestServlet(hs).register(http_server)
    PasswordRestServlet(hs).register(http_server)
    DeactivateAccountRestServlet(hs).register(http_server)
    EmailThreepidRequestTokenRestServlet(hs).register(http_server)
    MsisdnThreepidRequestTokenRestServlet(hs).register(http_server)
    ThreepidRestServlet(hs).register(http_server)
    ThreepidDeleteRestServlet(hs).register(http_server)
    WhoamiRestServlet(hs).register(http_server)
