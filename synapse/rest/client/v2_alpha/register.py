# -*- coding: utf-8 -*-
# Copyright 2015 - 2016 OpenMarket Ltd
# Copyright 2017 Vector Creations Ltd
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

import hmac
import logging
from hashlib import sha1

from six import string_types

from twisted.internet import defer

import synapse
import synapse.types
from synapse.api.constants import LoginType
from synapse.api.errors import (
    Codes,
    LimitExceededError,
    SynapseError,
    UnrecognizedRequestError,
)
from synapse.config.server import is_threepid_reserved
from synapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_json_object_from_request,
    parse_string,
)
from synapse.util.msisdn import phone_number_to_msisdn
from synapse.util.ratelimitutils import FederationRateLimiter
from synapse.util.threepids import check_3pid_allowed

from ._base import client_v2_patterns, interactive_auth_handler

# We ought to be using hmac.compare_digest() but on older pythons it doesn't
# exist. It's a _really minor_ security flaw to use plain string comparison
# because the timing attack is so obscured by all the other code here it's
# unlikely to make much difference
if hasattr(hmac, "compare_digest"):
    compare_digest = hmac.compare_digest
else:
    def compare_digest(a, b):
        return a == b


logger = logging.getLogger(__name__)


class EmailRegisterRequestTokenRestServlet(RestServlet):
    PATTERNS = client_v2_patterns("/register/email/requestToken$")

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        super(EmailRegisterRequestTokenRestServlet, self).__init__()
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
                "Your email domain is not authorized to register on this server",
                Codes.THREEPID_DENIED,
            )

        existingUid = yield self.hs.get_datastore().get_user_id_by_threepid(
            'email', body['email']
        )

        if existingUid is not None:
            raise SynapseError(400, "Email is already in use", Codes.THREEPID_IN_USE)

        ret = yield self.identity_handler.requestEmailToken(**body)
        defer.returnValue((200, ret))


class MsisdnRegisterRequestTokenRestServlet(RestServlet):
    PATTERNS = client_v2_patterns("/register/msisdn/requestToken$")

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        super(MsisdnRegisterRequestTokenRestServlet, self).__init__()
        self.hs = hs
        self.identity_handler = hs.get_handlers().identity_handler

    @defer.inlineCallbacks
    def on_POST(self, request):
        body = parse_json_object_from_request(request)

        assert_params_in_dict(body, [
            'id_server', 'client_secret',
            'country', 'phone_number',
            'send_attempt',
        ])

        msisdn = phone_number_to_msisdn(body['country'], body['phone_number'])

        if not check_3pid_allowed(self.hs, "msisdn", msisdn):
            raise SynapseError(
                403,
                "Phone numbers are not authorized to register on this server",
                Codes.THREEPID_DENIED,
            )

        existingUid = yield self.hs.get_datastore().get_user_id_by_threepid(
            'msisdn', msisdn
        )

        if existingUid is not None:
            raise SynapseError(
                400, "Phone number is already in use", Codes.THREEPID_IN_USE
            )

        ret = yield self.identity_handler.requestMsisdnToken(**body)
        defer.returnValue((200, ret))


class UsernameAvailabilityRestServlet(RestServlet):
    PATTERNS = client_v2_patterns("/register/available")

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        super(UsernameAvailabilityRestServlet, self).__init__()
        self.hs = hs
        self.registration_handler = hs.get_registration_handler()
        self.ratelimiter = FederationRateLimiter(
            hs.get_clock(),
            # Time window of 2s
            window_size=2000,
            # Artificially delay requests if rate > sleep_limit/window_size
            sleep_limit=1,
            # Amount of artificial delay to apply
            sleep_msec=1000,
            # Error with 429 if more than reject_limit requests are queued
            reject_limit=1,
            # Allow 1 request at a time
            concurrent_requests=1,
        )

    @defer.inlineCallbacks
    def on_GET(self, request):
        ip = self.hs.get_ip_from_request(request)
        with self.ratelimiter.ratelimit(ip) as wait_deferred:
            yield wait_deferred

            username = parse_string(request, "username", required=True)

            yield self.registration_handler.check_username(username)

            defer.returnValue((200, {"available": True}))


class RegisterRestServlet(RestServlet):
    PATTERNS = client_v2_patterns("/register$")

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        super(RegisterRestServlet, self).__init__()

        self.hs = hs
        self.auth = hs.get_auth()
        self.store = hs.get_datastore()
        self.auth_handler = hs.get_auth_handler()
        self.registration_handler = hs.get_registration_handler()
        self.identity_handler = hs.get_handlers().identity_handler
        self.room_member_handler = hs.get_room_member_handler()
        self.macaroon_gen = hs.get_macaroon_generator()
        self.ratelimiter = hs.get_registration_ratelimiter()
        self.clock = hs.get_clock()

    @interactive_auth_handler
    @defer.inlineCallbacks
    def on_POST(self, request):
        body = parse_json_object_from_request(request)

        client_addr = request.getClientIP()

        time_now = self.clock.time()

        allowed, time_allowed = self.ratelimiter.can_do_action(
            client_addr, time_now_s=time_now,
            rate_hz=self.hs.config.rc_registration.per_second,
            burst_count=self.hs.config.rc_registration.burst_count,
            update=False,
        )

        if not allowed:
            raise LimitExceededError(
                retry_after_ms=int(1000 * (time_allowed - time_now)),
            )

        kind = b"user"
        if b"kind" in request.args:
            kind = request.args[b"kind"][0]

        if kind == b"guest":
            ret = yield self._do_guest_registration(body, address=client_addr)
            defer.returnValue(ret)
            return
        elif kind != b"user":
            raise UnrecognizedRequestError(
                "Do not understand membership kind: %s" % (kind,)
            )

        # we do basic sanity checks here because the auth layer will store these
        # in sessions. Pull out the username/password provided to us.
        desired_password = None
        if 'password' in body:
            if (not isinstance(body['password'], string_types) or
                    len(body['password']) > 512):
                raise SynapseError(400, "Invalid password")
            desired_password = body["password"]

        desired_username = None
        if 'username' in body:
            if (not isinstance(body['username'], string_types) or
                    len(body['username']) > 512):
                raise SynapseError(400, "Invalid username")
            desired_username = body['username']

        appservice = None
        if self.auth.has_access_token(request):
            appservice = yield self.auth.get_appservice_by_req(request)

        # fork off as soon as possible for ASes and shared secret auth which
        # have completely different registration flows to normal users

        # == Application Service Registration ==
        if appservice:
            # Set the desired user according to the AS API (which uses the
            # 'user' key not 'username'). Since this is a new addition, we'll
            # fallback to 'username' if they gave one.
            desired_username = body.get("user", desired_username)

            # XXX we should check that desired_username is valid. Currently
            # we give appservices carte blanche for any insanity in mxids,
            # because the IRC bridges rely on being able to register stupid
            # IDs.

            access_token = self.auth.get_access_token_from_request(request)

            if isinstance(desired_username, string_types):
                result = yield self._do_appservice_registration(
                    desired_username, access_token, body
                )
            defer.returnValue((200, result))  # we throw for non 200 responses
            return

        # for either shared secret or regular registration, downcase the
        # provided username before attempting to register it. This should mean
        # that people who try to register with upper-case in their usernames
        # don't get a nasty surprise. (Note that we treat username
        # case-insenstively in login, so they are free to carry on imagining
        # that their username is CrAzYh4cKeR if that keeps them happy)
        if desired_username is not None:
            desired_username = desired_username.lower()

        # == Shared Secret Registration == (e.g. create new user scripts)
        if 'mac' in body:
            # FIXME: Should we really be determining if this is shared secret
            # auth based purely on the 'mac' key?
            result = yield self._do_shared_secret_registration(
                desired_username, desired_password, body
            )
            defer.returnValue((200, result))  # we throw for non 200 responses
            return

        # == Normal User Registration == (everyone else)
        if not self.hs.config.enable_registration:
            raise SynapseError(403, "Registration has been disabled")

        guest_access_token = body.get("guest_access_token", None)

        if (
            'initial_device_display_name' in body and
            'password' not in body
        ):
            # ignore 'initial_device_display_name' if sent without
            # a password to work around a client bug where it sent
            # the 'initial_device_display_name' param alone, wiping out
            # the original registration params
            logger.warn("Ignoring initial_device_display_name without password")
            del body['initial_device_display_name']

        session_id = self.auth_handler.get_session_id(body)
        registered_user_id = None
        if session_id:
            # if we get a registered user id out of here, it means we previously
            # registered a user for this session, so we could just return the
            # user here. We carry on and go through the auth checks though,
            # for paranoia.
            registered_user_id = self.auth_handler.get_session_data(
                session_id, "registered_user_id", None
            )

        if desired_username is not None:
            yield self.registration_handler.check_username(
                desired_username,
                guest_access_token=guest_access_token,
                assigned_user_id=registered_user_id,
            )

        # FIXME: need a better error than "no auth flow found" for scenarios
        # where we required 3PID for registration but the user didn't give one
        require_email = 'email' in self.hs.config.registrations_require_3pid
        require_msisdn = 'msisdn' in self.hs.config.registrations_require_3pid

        show_msisdn = True
        if self.hs.config.disable_msisdn_registration:
            show_msisdn = False
            require_msisdn = False

        flows = []
        if self.hs.config.enable_registration_captcha:
            # only support 3PIDless registration if no 3PIDs are required
            if not require_email and not require_msisdn:
                flows.extend([[LoginType.RECAPTCHA]])
            # only support the email-only flow if we don't require MSISDN 3PIDs
            if not require_msisdn:
                flows.extend([[LoginType.EMAIL_IDENTITY, LoginType.RECAPTCHA]])

            if show_msisdn:
                # only support the MSISDN-only flow if we don't require email 3PIDs
                if not require_email:
                    flows.extend([[LoginType.MSISDN, LoginType.RECAPTCHA]])
                # always let users provide both MSISDN & email
                flows.extend([
                    [LoginType.MSISDN, LoginType.EMAIL_IDENTITY, LoginType.RECAPTCHA],
                ])
        else:
            # only support 3PIDless registration if no 3PIDs are required
            if not require_email and not require_msisdn:
                flows.extend([[LoginType.DUMMY]])
            # only support the email-only flow if we don't require MSISDN 3PIDs
            if not require_msisdn:
                flows.extend([[LoginType.EMAIL_IDENTITY]])

            if show_msisdn:
                # only support the MSISDN-only flow if we don't require email 3PIDs
                if not require_email or require_msisdn:
                    flows.extend([[LoginType.MSISDN]])
                # always let users provide both MSISDN & email
                flows.extend([
                    [LoginType.MSISDN, LoginType.EMAIL_IDENTITY]
                ])

        # Append m.login.terms to all flows if we're requiring consent
        if self.hs.config.user_consent_at_registration:
            new_flows = []
            for flow in flows:
                flow.append(LoginType.TERMS)
            flows.extend(new_flows)

        auth_result, params, session_id = yield self.auth_handler.check_auth(
            flows, body, self.hs.get_ip_from_request(request)
        )

        # Check that we're not trying to register a denied 3pid.
        #
        # the user-facing checks will probably already have happened in
        # /register/email/requestToken when we requested a 3pid, but that's not
        # guaranteed.
        #
        # Also check that we're not trying to register a 3pid that's already
        # been registered.
        #
        # This has probably happened in /register/email/requestToken as well,
        # but if a user hits this endpoint twice then clicks on each link from
        # the two activation emails, they would register the same 3pid twice.

        if auth_result:
            for login_type in [LoginType.EMAIL_IDENTITY, LoginType.MSISDN]:
                if login_type in auth_result:
                    medium = auth_result[login_type]['medium']
                    address = auth_result[login_type]['address']

                    if not check_3pid_allowed(self.hs, medium, address):
                        raise SynapseError(
                            403,
                            "Third party identifiers (email/phone numbers)" +
                            " are not authorized on this server",
                            Codes.THREEPID_DENIED,
                        )

                    existingUid = yield self.store.get_user_id_by_threepid(
                        medium, address,
                    )

                    if existingUid is not None:
                        raise SynapseError(
                            400,
                            "%s is already in use" % medium,
                            Codes.THREEPID_IN_USE,
                        )

        if registered_user_id is not None:
            logger.info(
                "Already registered user ID %r for this session",
                registered_user_id
            )
            # don't re-register the threepids
            registered = False
        else:
            # NB: This may be from the auth handler and NOT from the POST
            assert_params_in_dict(params, ["password"])

            desired_username = params.get("username", None)
            guest_access_token = params.get("guest_access_token", None)
            new_password = params.get("password", None)

            if desired_username is not None:
                desired_username = desired_username.lower()

            threepid = None
            if auth_result:
                threepid = auth_result.get(LoginType.EMAIL_IDENTITY)

            (registered_user_id, _) = yield self.registration_handler.register(
                localpart=desired_username,
                password=new_password,
                guest_access_token=guest_access_token,
                generate_token=False,
                threepid=threepid,
                address=client_addr,
            )
            # Necessary due to auth checks prior to the threepid being
            # written to the db
            if threepid:
                if is_threepid_reserved(
                    self.hs.config.mau_limits_reserved_threepids, threepid
                ):
                    yield self.store.upsert_monthly_active_user(registered_user_id)

            # remember that we've now registered that user account, and with
            #  what user ID (since the user may not have specified)
            self.auth_handler.set_session_data(
                session_id, "registered_user_id", registered_user_id
            )

            registered = True

        return_dict = yield self._create_registration_details(
            registered_user_id, params
        )

        if registered:
            yield self.registration_handler.post_registration_actions(
                user_id=registered_user_id,
                auth_result=auth_result,
                access_token=return_dict.get("access_token"),
                bind_email=params.get("bind_email"),
                bind_msisdn=params.get("bind_msisdn"),
            )

        defer.returnValue((200, return_dict))

    def on_OPTIONS(self, _):
        return 200, {}

    @defer.inlineCallbacks
    def _do_appservice_registration(self, username, as_token, body):
        user_id = yield self.registration_handler.appservice_register(
            username, as_token
        )
        defer.returnValue((yield self._create_registration_details(user_id, body)))

    @defer.inlineCallbacks
    def _do_shared_secret_registration(self, username, password, body):
        if not self.hs.config.registration_shared_secret:
            raise SynapseError(400, "Shared secret registration is not enabled")
        if not username:
            raise SynapseError(
                400, "username must be specified", errcode=Codes.BAD_JSON,
            )

        # use the username from the original request rather than the
        # downcased one in `username` for the mac calculation
        user = body["username"].encode("utf-8")

        # str() because otherwise hmac complains that 'unicode' does not
        # have the buffer interface
        got_mac = str(body["mac"])

        # FIXME this is different to the /v1/register endpoint, which
        # includes the password and admin flag in the hashed text. Why are
        # these different?
        want_mac = hmac.new(
            key=self.hs.config.registration_shared_secret.encode(),
            msg=user,
            digestmod=sha1,
        ).hexdigest()

        if not compare_digest(want_mac, got_mac):
            raise SynapseError(
                403, "HMAC incorrect",
            )

        (user_id, _) = yield self.registration_handler.register(
            localpart=username, password=password, generate_token=False,
        )

        result = yield self._create_registration_details(user_id, body)
        defer.returnValue(result)

    @defer.inlineCallbacks
    def _create_registration_details(self, user_id, params):
        """Complete registration of newly-registered user

        Allocates device_id if one was not given; also creates access_token.

        Args:
            (str) user_id: full canonical @user:id
            (object) params: registration parameters, from which we pull
                device_id, initial_device_name and inhibit_login
        Returns:
            defer.Deferred: (object) dictionary for response from /register
        """
        result = {
            "user_id": user_id,
            "home_server": self.hs.hostname,
        }
        if not params.get("inhibit_login", False):
            device_id = params.get("device_id")
            initial_display_name = params.get("initial_device_display_name")
            device_id, access_token = yield self.registration_handler.register_device(
                user_id, device_id, initial_display_name, is_guest=False,
            )

            result.update({
                "access_token": access_token,
                "device_id": device_id,
            })
        defer.returnValue(result)

    @defer.inlineCallbacks
    def _do_guest_registration(self, params, address=None):
        if not self.hs.config.allow_guest_access:
            raise SynapseError(403, "Guest access is disabled")
        user_id, _ = yield self.registration_handler.register(
            generate_token=False,
            make_guest=True,
            address=address,
        )

        # we don't allow guests to specify their own device_id, because
        # we have nowhere to store it.
        device_id = synapse.api.auth.GUEST_DEVICE_ID
        initial_display_name = params.get("initial_device_display_name")
        device_id, access_token = yield self.registration_handler.register_device(
            user_id, device_id, initial_display_name, is_guest=True,
        )

        defer.returnValue((200, {
            "user_id": user_id,
            "device_id": device_id,
            "access_token": access_token,
            "home_server": self.hs.hostname,
        }))


def register_servlets(hs, http_server):
    EmailRegisterRequestTokenRestServlet(hs).register(http_server)
    MsisdnRegisterRequestTokenRestServlet(hs).register(http_server)
    UsernameAvailabilityRestServlet(hs).register(http_server)
    RegisterRestServlet(hs).register(http_server)
