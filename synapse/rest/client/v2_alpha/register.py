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
from synapse.api.errors import Codes, SynapseError, UnrecognizedRequestError
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
        self.registration_handler = hs.get_handlers().registration_handler
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
        self.registration_handler = hs.get_handlers().registration_handler
        self.identity_handler = hs.get_handlers().identity_handler
        self.room_member_handler = hs.get_room_member_handler()
        self.device_handler = hs.get_device_handler()
        self.macaroon_gen = hs.get_macaroon_generator()

    @interactive_auth_handler
    @defer.inlineCallbacks
    def on_POST(self, request):
        body = parse_json_object_from_request(request)

        kind = b"user"
        if b"kind" in request.args:
            kind = request.args[b"kind"][0]

        if kind == b"guest":
            ret = yield self._do_guest_registration(body)
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

        # Only give msisdn flows if the x_show_msisdn flag is given:
        # this is a hack to work around the fact that clients were shipped
        # that use fallback registration if they see any flows that they don't
        # recognise, which means we break registration for these clients if we
        # advertise msisdn flows. Once usage of Riot iOS <=0.3.9 and Riot
        # Android <=0.6.9 have fallen below an acceptable threshold, this
        # parameter should go away and we should always advertise msisdn flows.
        show_msisdn = False
        if 'x_show_msisdn' in body and body['x_show_msisdn']:
            show_msisdn = True

        # FIXME: need a better error than "no auth flow found" for scenarios
        # where we required 3PID for registration but the user didn't give one
        require_email = 'email' in self.hs.config.registrations_require_3pid
        require_msisdn = 'msisdn' in self.hs.config.registrations_require_3pid

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

        auth_result, params, session_id = yield self.auth_handler.check_auth(
            flows, body, self.hs.get_ip_from_request(request)
        )

        # Check that we're not trying to register a denied 3pid.
        #
        # the user-facing checks will probably already have happened in
        # /register/email/requestToken when we requested a 3pid, but that's not
        # guaranteed.

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

        if registered_user_id is not None:
            logger.info(
                "Already registered user ID %r for this session",
                registered_user_id
            )
            # don't re-register the threepids
            add_email = False
            add_msisdn = False
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
            )
            # Necessary due to auth checks prior to the threepid being
            # written to the db
            if is_threepid_reserved(self.hs.config, threepid):
                yield self.store.upsert_monthly_active_user(registered_user_id)

            # remember that we've now registered that user account, and with
            #  what user ID (since the user may not have specified)
            self.auth_handler.set_session_data(
                session_id, "registered_user_id", registered_user_id
            )

            add_email = True
            add_msisdn = True

        return_dict = yield self._create_registration_details(
            registered_user_id, params
        )

        if add_email and auth_result and LoginType.EMAIL_IDENTITY in auth_result:
            threepid = auth_result[LoginType.EMAIL_IDENTITY]
            yield self._register_email_threepid(
                registered_user_id, threepid, return_dict["access_token"],
                params.get("bind_email")
            )

        if add_msisdn and auth_result and LoginType.MSISDN in auth_result:
            threepid = auth_result[LoginType.MSISDN]
            yield self._register_msisdn_threepid(
                registered_user_id, threepid, return_dict["access_token"],
                params.get("bind_msisdn")
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
    def _register_email_threepid(self, user_id, threepid, token, bind_email):
        """Add an email address as a 3pid identifier

        Also adds an email pusher for the email address, if configured in the
        HS config

        Also optionally binds emails to the given user_id on the identity server

        Args:
            user_id (str): id of user
            threepid (object): m.login.email.identity auth response
            token (str): access_token for the user
            bind_email (bool): true if the client requested the email to be
                bound at the identity server
        Returns:
            defer.Deferred:
        """
        reqd = ('medium', 'address', 'validated_at')
        if any(x not in threepid for x in reqd):
            # This will only happen if the ID server returns a malformed response
            logger.info("Can't add incomplete 3pid")
            return

        yield self.auth_handler.add_threepid(
            user_id,
            threepid['medium'],
            threepid['address'],
            threepid['validated_at'],
        )

        # And we add an email pusher for them by default, but only
        # if email notifications are enabled (so people don't start
        # getting mail spam where they weren't before if email
        # notifs are set up on a home server)
        if (self.hs.config.email_enable_notifs and
                self.hs.config.email_notif_for_new_users):
            # Pull the ID of the access token back out of the db
            # It would really make more sense for this to be passed
            # up when the access token is saved, but that's quite an
            # invasive change I'd rather do separately.
            user_tuple = yield self.store.get_user_by_access_token(
                token
            )
            token_id = user_tuple["token_id"]

            yield self.hs.get_pusherpool().add_pusher(
                user_id=user_id,
                access_token=token_id,
                kind="email",
                app_id="m.email",
                app_display_name="Email Notifications",
                device_display_name=threepid["address"],
                pushkey=threepid["address"],
                lang=None,  # We don't know a user's language here
                data={},
            )

        if bind_email:
            logger.info("bind_email specified: binding")
            logger.debug("Binding emails %s to %s" % (
                threepid, user_id
            ))
            yield self.identity_handler.bind_threepid(
                threepid['threepid_creds'], user_id
            )
        else:
            logger.info("bind_email not specified: not binding email")

    @defer.inlineCallbacks
    def _register_msisdn_threepid(self, user_id, threepid, token, bind_msisdn):
        """Add a phone number as a 3pid identifier

        Also optionally binds msisdn to the given user_id on the identity server

        Args:
            user_id (str): id of user
            threepid (object): m.login.msisdn auth response
            token (str): access_token for the user
            bind_email (bool): true if the client requested the email to be
                bound at the identity server
        Returns:
            defer.Deferred:
        """
        try:
            assert_params_in_dict(threepid, ['medium', 'address', 'validated_at'])
        except SynapseError as ex:
            if ex.errcode == Codes.MISSING_PARAM:
                # This will only happen if the ID server returns a malformed response
                logger.info("Can't add incomplete 3pid")
                defer.returnValue(None)
            raise

        yield self.auth_handler.add_threepid(
            user_id,
            threepid['medium'],
            threepid['address'],
            threepid['validated_at'],
        )

        if bind_msisdn:
            logger.info("bind_msisdn specified: binding")
            logger.debug("Binding msisdn %s to %s", threepid, user_id)
            yield self.identity_handler.bind_threepid(
                threepid['threepid_creds'], user_id
            )
        else:
            logger.info("bind_msisdn not specified: not binding msisdn")

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
            device_id = yield self._register_device(user_id, params)

            access_token = (
                yield self.auth_handler.get_access_token_for_user_id(
                    user_id, device_id=device_id,
                )
            )

            result.update({
                "access_token": access_token,
                "device_id": device_id,
            })
        defer.returnValue(result)

    def _register_device(self, user_id, params):
        """Register a device for a user.

        This is called after the user's credentials have been validated, but
        before the access token has been issued.

        Args:
            (str) user_id: full canonical @user:id
            (object) params: registration parameters, from which we pull
                device_id and initial_device_name
        Returns:
            defer.Deferred: (str) device_id
        """
        # register the user's device
        device_id = params.get("device_id")
        initial_display_name = params.get("initial_device_display_name")
        return self.device_handler.check_device_registered(
            user_id, device_id, initial_display_name
        )

    @defer.inlineCallbacks
    def _do_guest_registration(self, params):
        if not self.hs.config.allow_guest_access:
            raise SynapseError(403, "Guest access is disabled")
        user_id, _ = yield self.registration_handler.register(
            generate_token=False,
            make_guest=True
        )

        # we don't allow guests to specify their own device_id, because
        # we have nowhere to store it.
        device_id = synapse.api.auth.GUEST_DEVICE_ID
        initial_display_name = params.get("initial_device_display_name")
        yield self.device_handler.check_device_registered(
            user_id, device_id, initial_display_name
        )

        access_token = self.macaroon_gen.generate_access_token(
            user_id, ["guest = true"]
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
