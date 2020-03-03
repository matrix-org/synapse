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
import xml.etree.ElementTree as ET

from six.moves import urllib

from twisted.web.client import PartialDownloadError

from synapse.api.errors import Codes, LoginError, SynapseError
from synapse.api.ratelimiting import Ratelimiter
from synapse.http.server import finish_request
from synapse.http.servlet import (
    RestServlet,
    parse_json_object_from_request,
    parse_string,
)
from synapse.push.mailer import load_jinja2_templates
from synapse.rest.client.v2_alpha._base import client_patterns
from synapse.rest.well_known import WellKnownBuilder
from synapse.types import UserID, map_username_to_mxid_localpart
from synapse.util.msisdn import phone_number_to_msisdn

logger = logging.getLogger(__name__)


def login_submission_legacy_convert(submission):
    """
    If the input login submission is an old style object
    (ie. with top-level user / medium / address) convert it
    to a typed object.
    """
    if "user" in submission:
        submission["identifier"] = {"type": "m.id.user", "user": submission["user"]}
        del submission["user"]

    if "medium" in submission and "address" in submission:
        submission["identifier"] = {
            "type": "m.id.thirdparty",
            "medium": submission["medium"],
            "address": submission["address"],
        }
        del submission["medium"]
        del submission["address"]


def login_id_thirdparty_from_phone(identifier):
    """
    Convert a phone login identifier type to a generic threepid identifier
    Args:
        identifier(dict): Login identifier dict of type 'm.id.phone'

    Returns: Login identifier dict of type 'm.id.threepid'
    """
    if "country" not in identifier or "number" not in identifier:
        raise SynapseError(400, "Invalid phone-type identifier")

    msisdn = phone_number_to_msisdn(identifier["country"], identifier["number"])

    return {"type": "m.id.thirdparty", "medium": "msisdn", "address": msisdn}


class LoginRestServlet(RestServlet):
    PATTERNS = client_patterns("/login$", v1=True)
    CAS_TYPE = "m.login.cas"
    SSO_TYPE = "m.login.sso"
    TOKEN_TYPE = "m.login.token"
    JWT_TYPE = "m.login.jwt"

    def __init__(self, hs):
        super(LoginRestServlet, self).__init__()
        self.hs = hs
        self.jwt_enabled = hs.config.jwt_enabled
        self.jwt_secret = hs.config.jwt_secret
        self.jwt_algorithm = hs.config.jwt_algorithm
        self.saml2_enabled = hs.config.saml2_enabled
        self.cas_enabled = hs.config.cas_enabled
        self.auth_handler = self.hs.get_auth_handler()
        self.registration_handler = hs.get_registration_handler()
        self.handlers = hs.get_handlers()
        self._clock = hs.get_clock()
        self._well_known_builder = WellKnownBuilder(hs)
        self._address_ratelimiter = Ratelimiter()
        self._account_ratelimiter = Ratelimiter()
        self._failed_attempts_ratelimiter = Ratelimiter()

    def on_GET(self, request):
        flows = []
        if self.jwt_enabled:
            flows.append({"type": LoginRestServlet.JWT_TYPE})
        if self.saml2_enabled:
            flows.append({"type": LoginRestServlet.SSO_TYPE})
            flows.append({"type": LoginRestServlet.TOKEN_TYPE})
        if self.cas_enabled:
            flows.append({"type": LoginRestServlet.SSO_TYPE})

            # we advertise CAS for backwards compat, though MSC1721 renamed it
            # to SSO.
            flows.append({"type": LoginRestServlet.CAS_TYPE})

            # While its valid for us to advertise this login type generally,
            # synapse currently only gives out these tokens as part of the
            # CAS login flow.
            # Generally we don't want to advertise login flows that clients
            # don't know how to implement, since they (currently) will always
            # fall back to the fallback API if they don't understand one of the
            # login flow types returned.
            flows.append({"type": LoginRestServlet.TOKEN_TYPE})

        flows.extend(
            ({"type": t} for t in self.auth_handler.get_supported_login_types())
        )

        return 200, {"flows": flows}

    def on_OPTIONS(self, request):
        return 200, {}

    async def on_POST(self, request):
        self._address_ratelimiter.ratelimit(
            request.getClientIP(),
            time_now_s=self.hs.clock.time(),
            rate_hz=self.hs.config.rc_login_address.per_second,
            burst_count=self.hs.config.rc_login_address.burst_count,
            update=True,
        )

        login_submission = parse_json_object_from_request(request)
        try:
            if self.jwt_enabled and (
                login_submission["type"] == LoginRestServlet.JWT_TYPE
            ):
                result = await self.do_jwt_login(login_submission)
            elif login_submission["type"] == LoginRestServlet.TOKEN_TYPE:
                result = await self.do_token_login(login_submission)
            else:
                result = await self._do_other_login(login_submission)
        except KeyError:
            raise SynapseError(400, "Missing JSON keys.")

        well_known_data = self._well_known_builder.get_well_known()
        if well_known_data:
            result["well_known"] = well_known_data
        return 200, result

    async def _do_other_login(self, login_submission):
        """Handle non-token/saml/jwt logins

        Args:
            login_submission:

        Returns:
            dict: HTTP response
        """
        # Log the request we got, but only certain fields to minimise the chance of
        # logging someone's password (even if they accidentally put it in the wrong
        # field)
        logger.info(
            "Got login request with identifier: %r, medium: %r, address: %r, user: %r",
            login_submission.get("identifier"),
            login_submission.get("medium"),
            login_submission.get("address"),
            login_submission.get("user"),
        )
        login_submission_legacy_convert(login_submission)

        if "identifier" not in login_submission:
            raise SynapseError(400, "Missing param: identifier")

        identifier = login_submission["identifier"]
        if "type" not in identifier:
            raise SynapseError(400, "Login identifier has no type")

        # convert phone type identifiers to generic threepids
        if identifier["type"] == "m.id.phone":
            identifier = login_id_thirdparty_from_phone(identifier)

        # convert threepid identifiers to user IDs
        if identifier["type"] == "m.id.thirdparty":
            address = identifier.get("address")
            medium = identifier.get("medium")

            if medium is None or address is None:
                raise SynapseError(400, "Invalid thirdparty identifier")

            if medium == "email":
                # For emails, transform the address to lowercase.
                # We store all email addreses as lowercase in the DB.
                # (See add_threepid in synapse/handlers/auth.py)
                address = address.lower()

            # We also apply account rate limiting using the 3PID as a key, as
            # otherwise using 3PID bypasses the ratelimiting based on user ID.
            self._failed_attempts_ratelimiter.ratelimit(
                (medium, address),
                time_now_s=self._clock.time(),
                rate_hz=self.hs.config.rc_login_failed_attempts.per_second,
                burst_count=self.hs.config.rc_login_failed_attempts.burst_count,
                update=False,
            )

            # Check for login providers that support 3pid login types
            (
                canonical_user_id,
                callback_3pid,
            ) = await self.auth_handler.check_password_provider_3pid(
                medium, address, login_submission["password"]
            )
            if canonical_user_id:
                # Authentication through password provider and 3pid succeeded

                result = await self._complete_login(
                    canonical_user_id, login_submission, callback_3pid
                )
                return result

            # No password providers were able to handle this 3pid
            # Check local store
            user_id = await self.hs.get_datastore().get_user_id_by_threepid(
                medium, address
            )
            if not user_id:
                logger.warning(
                    "unknown 3pid identifier medium %s, address %r", medium, address
                )
                # We mark that we've failed to log in here, as
                # `check_password_provider_3pid` might have returned `None` due
                # to an incorrect password, rather than the account not
                # existing.
                #
                # If it returned None but the 3PID was bound then we won't hit
                # this code path, which is fine as then the per-user ratelimit
                # will kick in below.
                self._failed_attempts_ratelimiter.can_do_action(
                    (medium, address),
                    time_now_s=self._clock.time(),
                    rate_hz=self.hs.config.rc_login_failed_attempts.per_second,
                    burst_count=self.hs.config.rc_login_failed_attempts.burst_count,
                    update=True,
                )
                raise LoginError(403, "", errcode=Codes.FORBIDDEN)

            identifier = {"type": "m.id.user", "user": user_id}

        # by this point, the identifier should be an m.id.user: if it's anything
        # else, we haven't understood it.
        if identifier["type"] != "m.id.user":
            raise SynapseError(400, "Unknown login identifier type")
        if "user" not in identifier:
            raise SynapseError(400, "User identifier is missing 'user' key")

        if identifier["user"].startswith("@"):
            qualified_user_id = identifier["user"]
        else:
            qualified_user_id = UserID(identifier["user"], self.hs.hostname).to_string()

        # Check if we've hit the failed ratelimit (but don't update it)
        self._failed_attempts_ratelimiter.ratelimit(
            qualified_user_id.lower(),
            time_now_s=self._clock.time(),
            rate_hz=self.hs.config.rc_login_failed_attempts.per_second,
            burst_count=self.hs.config.rc_login_failed_attempts.burst_count,
            update=False,
        )

        try:
            canonical_user_id, callback = await self.auth_handler.validate_login(
                identifier["user"], login_submission
            )
        except LoginError:
            # The user has failed to log in, so we need to update the rate
            # limiter. Using `can_do_action` avoids us raising a ratelimit
            # exception and masking the LoginError. The actual ratelimiting
            # should have happened above.
            self._failed_attempts_ratelimiter.can_do_action(
                qualified_user_id.lower(),
                time_now_s=self._clock.time(),
                rate_hz=self.hs.config.rc_login_failed_attempts.per_second,
                burst_count=self.hs.config.rc_login_failed_attempts.burst_count,
                update=True,
            )
            raise

        result = await self._complete_login(
            canonical_user_id, login_submission, callback
        )
        return result

    async def _complete_login(
        self, user_id, login_submission, callback=None, create_non_existant_users=False
    ):
        """Called when we've successfully authed the user and now need to
        actually login them in (e.g. create devices). This gets called on
        all succesful logins.

        Applies the ratelimiting for succesful login attempts against an
        account.

        Args:
            user_id (str): ID of the user to register.
            login_submission (dict): Dictionary of login information.
            callback (func|None): Callback function to run after registration.
            create_non_existant_users (bool): Whether to create the user if
                they don't exist. Defaults to False.

        Returns:
            result (Dict[str,str]): Dictionary of account information after
                successful registration.
        """

        # Before we actually log them in we check if they've already logged in
        # too often. This happens here rather than before as we don't
        # necessarily know the user before now.
        self._account_ratelimiter.ratelimit(
            user_id.lower(),
            time_now_s=self._clock.time(),
            rate_hz=self.hs.config.rc_login_account.per_second,
            burst_count=self.hs.config.rc_login_account.burst_count,
            update=True,
        )

        if create_non_existant_users:
            user_id = await self.auth_handler.check_user_exists(user_id)
            if not user_id:
                user_id = await self.registration_handler.register_user(
                    localpart=UserID.from_string(user_id).localpart
                )

        device_id = login_submission.get("device_id")
        initial_display_name = login_submission.get("initial_device_display_name")
        device_id, access_token = await self.registration_handler.register_device(
            user_id, device_id, initial_display_name
        )

        result = {
            "user_id": user_id,
            "access_token": access_token,
            "home_server": self.hs.hostname,
            "device_id": device_id,
        }

        if callback is not None:
            await callback(result)

        return result

    async def do_token_login(self, login_submission):
        token = login_submission["token"]
        auth_handler = self.auth_handler
        user_id = await auth_handler.validate_short_term_login_token_and_get_user_id(
            token
        )

        result = await self._complete_login(user_id, login_submission)
        return result

    async def do_jwt_login(self, login_submission):
        token = login_submission.get("token", None)
        if token is None:
            raise LoginError(
                401, "Token field for JWT is missing", errcode=Codes.UNAUTHORIZED
            )

        import jwt
        from jwt.exceptions import InvalidTokenError

        try:
            payload = jwt.decode(
                token, self.jwt_secret, algorithms=[self.jwt_algorithm]
            )
        except jwt.ExpiredSignatureError:
            raise LoginError(401, "JWT expired", errcode=Codes.UNAUTHORIZED)
        except InvalidTokenError:
            raise LoginError(401, "Invalid JWT", errcode=Codes.UNAUTHORIZED)

        user = payload.get("sub", None)
        if user is None:
            raise LoginError(401, "Invalid JWT", errcode=Codes.UNAUTHORIZED)

        user_id = UserID(user, self.hs.hostname).to_string()
        result = await self._complete_login(
            user_id, login_submission, create_non_existant_users=True
        )
        return result


class BaseSSORedirectServlet(RestServlet):
    """Common base class for /login/sso/redirect impls"""

    PATTERNS = client_patterns("/login/(cas|sso)/redirect", v1=True)

    def on_GET(self, request):
        args = request.args
        if b"redirectUrl" not in args:
            return 400, "Redirect URL not specified for SSO auth"
        client_redirect_url = args[b"redirectUrl"][0]
        sso_url = self.get_sso_url(client_redirect_url)
        request.redirect(sso_url)
        finish_request(request)

    def get_sso_url(self, client_redirect_url):
        """Get the URL to redirect to, to perform SSO auth

        Args:
            client_redirect_url (bytes): the URL that we should redirect the
                client to when everything is done

        Returns:
            bytes: URL to redirect to
        """
        # to be implemented by subclasses
        raise NotImplementedError()


class CasRedirectServlet(BaseSSORedirectServlet):
    def __init__(self, hs):
        super(CasRedirectServlet, self).__init__()
        self.cas_server_url = hs.config.cas_server_url.encode("ascii")
        self.cas_service_url = hs.config.cas_service_url.encode("ascii")

    def get_sso_url(self, client_redirect_url):
        client_redirect_url_param = urllib.parse.urlencode(
            {b"redirectUrl": client_redirect_url}
        ).encode("ascii")
        hs_redirect_url = self.cas_service_url + b"/_matrix/client/r0/login/cas/ticket"
        service_param = urllib.parse.urlencode(
            {b"service": b"%s?%s" % (hs_redirect_url, client_redirect_url_param)}
        ).encode("ascii")
        return b"%s/login?%s" % (self.cas_server_url, service_param)


class CasTicketServlet(RestServlet):
    PATTERNS = client_patterns("/login/cas/ticket", v1=True)

    def __init__(self, hs):
        super(CasTicketServlet, self).__init__()
        self.cas_server_url = hs.config.cas_server_url
        self.cas_service_url = hs.config.cas_service_url
        self.cas_displayname_attribute = hs.config.cas_displayname_attribute
        self.cas_required_attributes = hs.config.cas_required_attributes
        self._sso_auth_handler = SSOAuthHandler(hs)
        self._http_client = hs.get_proxied_http_client()

    async def on_GET(self, request):
        client_redirect_url = parse_string(request, "redirectUrl", required=True)
        uri = self.cas_server_url + "/proxyValidate"
        args = {
            "ticket": parse_string(request, "ticket", required=True),
            "service": self.cas_service_url,
        }
        try:
            body = await self._http_client.get_raw(uri, args)
        except PartialDownloadError as pde:
            # Twisted raises this error if the connection is closed,
            # even if that's being used old-http style to signal end-of-data
            body = pde.response
        result = await self.handle_cas_response(request, body, client_redirect_url)
        return result

    def handle_cas_response(self, request, cas_response_body, client_redirect_url):
        user, attributes = self.parse_cas_response(cas_response_body)
        displayname = attributes.pop(self.cas_displayname_attribute, None)

        for required_attribute, required_value in self.cas_required_attributes.items():
            # If required attribute was not in CAS Response - Forbidden
            if required_attribute not in attributes:
                raise LoginError(401, "Unauthorized", errcode=Codes.UNAUTHORIZED)

            # Also need to check value
            if required_value is not None:
                actual_value = attributes[required_attribute]
                # If required attribute value does not match expected - Forbidden
                if required_value != actual_value:
                    raise LoginError(401, "Unauthorized", errcode=Codes.UNAUTHORIZED)

        return self._sso_auth_handler.on_successful_auth(
            user, request, client_redirect_url, displayname
        )

    def parse_cas_response(self, cas_response_body):
        user = None
        attributes = {}
        try:
            root = ET.fromstring(cas_response_body)
            if not root.tag.endswith("serviceResponse"):
                raise Exception("root of CAS response is not serviceResponse")
            success = root[0].tag.endswith("authenticationSuccess")
            for child in root[0]:
                if child.tag.endswith("user"):
                    user = child.text
                if child.tag.endswith("attributes"):
                    for attribute in child:
                        # ElementTree library expands the namespace in
                        # attribute tags to the full URL of the namespace.
                        # We don't care about namespace here and it will always
                        # be encased in curly braces, so we remove them.
                        tag = attribute.tag
                        if "}" in tag:
                            tag = tag.split("}")[1]
                        attributes[tag] = attribute.text
            if user is None:
                raise Exception("CAS response does not contain user")
        except Exception:
            logger.exception("Error parsing CAS response")
            raise LoginError(401, "Invalid CAS response", errcode=Codes.UNAUTHORIZED)
        if not success:
            raise LoginError(
                401, "Unsuccessful CAS response", errcode=Codes.UNAUTHORIZED
            )
        return user, attributes


class SAMLRedirectServlet(BaseSSORedirectServlet):
    PATTERNS = client_patterns("/login/sso/redirect", v1=True)

    def __init__(self, hs):
        self._saml_handler = hs.get_saml_handler()

    def get_sso_url(self, client_redirect_url):
        return self._saml_handler.handle_redirect_request(client_redirect_url)


class SSOAuthHandler(object):
    """
    Utility class for Resources and Servlets which handle the response from a SSO
    service

    Args:
        hs (synapse.server.HomeServer)
    """

    def __init__(self, hs):
        self._hostname = hs.hostname
        self._auth_handler = hs.get_auth_handler()
        self._registration_handler = hs.get_registration_handler()
        self._macaroon_gen = hs.get_macaroon_generator()

        # Load the redirect page HTML template
        self._template = load_jinja2_templates(
            hs.config.sso_redirect_confirm_template_dir, ["sso_redirect_confirm.html"],
        )[0]

        self._server_name = hs.config.server_name

        # cast to tuple for use with str.startswith
        self._whitelisted_sso_clients = tuple(hs.config.sso_client_whitelist)

    async def on_successful_auth(
        self, username, request, client_redirect_url, user_display_name=None
    ):
        """Called once the user has successfully authenticated with the SSO.

        Registers the user if necessary, and then returns a redirect (with
        a login token) to the client.

        Args:
            username (unicode|bytes): the remote user id. We'll map this onto
                something sane for a MXID localpath.

            request (SynapseRequest): the incoming request from the browser. We'll
                respond to it with a redirect.

            client_redirect_url (unicode): the redirect_url the client gave us when
                it first started the process.

            user_display_name (unicode|None): if set, and we have to register a new user,
                we will set their displayname to this.

        Returns:
            Deferred[none]: Completes once we have handled the request.
        """
        localpart = map_username_to_mxid_localpart(username)
        user_id = UserID(localpart, self._hostname).to_string()
        registered_user_id = await self._auth_handler.check_user_exists(user_id)
        if not registered_user_id:
            registered_user_id = await self._registration_handler.register_user(
                localpart=localpart, default_display_name=user_display_name
            )

        self._auth_handler.complete_sso_login(
            registered_user_id, request, client_redirect_url
        )


def register_servlets(hs, http_server):
    LoginRestServlet(hs).register(http_server)
    if hs.config.cas_enabled:
        CasRedirectServlet(hs).register(http_server)
        CasTicketServlet(hs).register(http_server)
    elif hs.config.saml2_enabled:
        SAMLRedirectServlet(hs).register(http_server)
