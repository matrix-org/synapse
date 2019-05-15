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

from twisted.internet import defer
from twisted.web.client import PartialDownloadError

from synapse.api.errors import Codes, LoginError, SynapseError
from synapse.api.ratelimiting import Ratelimiter
from synapse.http.server import finish_request
from synapse.http.servlet import (
    RestServlet,
    parse_json_object_from_request,
    parse_string,
)
from synapse.rest.well_known import WellKnownBuilder
from synapse.types import UserID, map_username_to_mxid_localpart
from synapse.util.msisdn import phone_number_to_msisdn

from .base import ClientV1RestServlet, client_path_patterns

logger = logging.getLogger(__name__)


def login_submission_legacy_convert(submission):
    """
    If the input login submission is an old style object
    (ie. with top-level user / medium / address) convert it
    to a typed object.
    """
    if "user" in submission:
        submission["identifier"] = {
            "type": "m.id.user",
            "user": submission["user"],
        }
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

    return {
        "type": "m.id.thirdparty",
        "medium": "msisdn",
        "address": msisdn,
    }


class LoginRestServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns("/login$")
    CAS_TYPE = "m.login.cas"
    SSO_TYPE = "m.login.sso"
    TOKEN_TYPE = "m.login.token"
    JWT_TYPE = "m.login.jwt"

    def __init__(self, hs):
        super(LoginRestServlet, self).__init__(hs)
        self.jwt_enabled = hs.config.jwt_enabled
        self.jwt_secret = hs.config.jwt_secret
        self.jwt_algorithm = hs.config.jwt_algorithm
        self.cas_enabled = hs.config.cas_enabled
        self.auth_handler = self.hs.get_auth_handler()
        self.registration_handler = hs.get_registration_handler()
        self.handlers = hs.get_handlers()
        self._well_known_builder = WellKnownBuilder(hs)
        self._address_ratelimiter = Ratelimiter()

    def on_GET(self, request):
        flows = []
        if self.jwt_enabled:
            flows.append({"type": LoginRestServlet.JWT_TYPE})
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

        flows.extend((
            {"type": t} for t in self.auth_handler.get_supported_login_types()
        ))

        return (200, {"flows": flows})

    def on_OPTIONS(self, request):
        return (200, {})

    @defer.inlineCallbacks
    def on_POST(self, request):
        self._address_ratelimiter.ratelimit(
            request.getClientIP(), time_now_s=self.hs.clock.time(),
            rate_hz=self.hs.config.rc_login_address.per_second,
            burst_count=self.hs.config.rc_login_address.burst_count,
            update=True,
        )

        login_submission = parse_json_object_from_request(request)
        try:
            if self.jwt_enabled and (login_submission["type"] ==
                                     LoginRestServlet.JWT_TYPE):
                result = yield self.do_jwt_login(login_submission)
            elif login_submission["type"] == LoginRestServlet.TOKEN_TYPE:
                result = yield self.do_token_login(login_submission)
            else:
                result = yield self._do_other_login(login_submission)
        except KeyError:
            raise SynapseError(400, "Missing JSON keys.")

        well_known_data = self._well_known_builder.get_well_known()
        if well_known_data:
            result["well_known"] = well_known_data
        defer.returnValue((200, result))

    @defer.inlineCallbacks
    def _do_other_login(self, login_submission):
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
            login_submission.get('identifier'),
            login_submission.get('medium'),
            login_submission.get('address'),
            login_submission.get('user'),
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
            address = identifier.get('address')
            medium = identifier.get('medium')

            if medium is None or address is None:
                raise SynapseError(400, "Invalid thirdparty identifier")

            if medium == 'email':
                # For emails, transform the address to lowercase.
                # We store all email addreses as lowercase in the DB.
                # (See add_threepid in synapse/handlers/auth.py)
                address = address.lower()

            # Check for login providers that support 3pid login types
            canonical_user_id, callback_3pid = (
                yield self.auth_handler.check_password_provider_3pid(
                    medium,
                    address,
                    login_submission["password"],
                )
            )
            if canonical_user_id:
                # Authentication through password provider and 3pid succeeded
                result = yield self._register_device_with_callback(
                    canonical_user_id, login_submission, callback_3pid,
                )
                defer.returnValue(result)

            # No password providers were able to handle this 3pid
            # Check local store
            user_id = yield self.hs.get_datastore().get_user_id_by_threepid(
                medium, address,
            )
            if not user_id:
                logger.warn(
                    "unknown 3pid identifier medium %s, address %r",
                    medium, address,
                )
                raise LoginError(403, "", errcode=Codes.FORBIDDEN)

            identifier = {
                "type": "m.id.user",
                "user": user_id,
            }

        # by this point, the identifier should be an m.id.user: if it's anything
        # else, we haven't understood it.
        if identifier["type"] != "m.id.user":
            raise SynapseError(400, "Unknown login identifier type")
        if "user" not in identifier:
            raise SynapseError(400, "User identifier is missing 'user' key")

        canonical_user_id, callback = yield self.auth_handler.validate_login(
            identifier["user"],
            login_submission,
        )

        result = yield self._register_device_with_callback(
            canonical_user_id, login_submission, callback,
        )
        defer.returnValue(result)

    @defer.inlineCallbacks
    def _register_device_with_callback(
        self,
        user_id,
        login_submission,
        callback=None,
    ):
        """ Registers a device with a given user_id. Optionally run a callback
        function after registration has completed.

        Args:
            user_id (str): ID of the user to register.
            login_submission (dict): Dictionary of login information.
            callback (func|None): Callback function to run after registration.

        Returns:
            result (Dict[str,str]): Dictionary of account information after
                successful registration.
        """
        device_id = login_submission.get("device_id")
        initial_display_name = login_submission.get("initial_device_display_name")
        device_id, access_token = yield self.registration_handler.register_device(
            user_id, device_id, initial_display_name,
        )

        result = {
            "user_id": user_id,
            "access_token": access_token,
            "home_server": self.hs.hostname,
            "device_id": device_id,
        }

        if callback is not None:
            yield callback(result)

        defer.returnValue(result)

    @defer.inlineCallbacks
    def do_token_login(self, login_submission):
        token = login_submission['token']
        auth_handler = self.auth_handler
        user_id = (
            yield auth_handler.validate_short_term_login_token_and_get_user_id(token)
        )

        device_id = login_submission.get("device_id")
        initial_display_name = login_submission.get("initial_device_display_name")
        device_id, access_token = yield self.registration_handler.register_device(
            user_id, device_id, initial_display_name,
        )

        result = {
            "user_id": user_id,  # may have changed
            "access_token": access_token,
            "home_server": self.hs.hostname,
            "device_id": device_id,
        }

        defer.returnValue(result)

    @defer.inlineCallbacks
    def do_jwt_login(self, login_submission):
        token = login_submission.get("token", None)
        if token is None:
            raise LoginError(
                401, "Token field for JWT is missing",
                errcode=Codes.UNAUTHORIZED
            )

        import jwt
        from jwt.exceptions import InvalidTokenError

        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
        except jwt.ExpiredSignatureError:
            raise LoginError(401, "JWT expired", errcode=Codes.UNAUTHORIZED)
        except InvalidTokenError:
            raise LoginError(401, "Invalid JWT", errcode=Codes.UNAUTHORIZED)

        user = payload.get("sub", None)
        if user is None:
            raise LoginError(401, "Invalid JWT", errcode=Codes.UNAUTHORIZED)

        user_id = UserID(user, self.hs.hostname).to_string()

        auth_handler = self.auth_handler
        registered_user_id = yield auth_handler.check_user_exists(user_id)
        if registered_user_id:
            device_id = login_submission.get("device_id")
            initial_display_name = login_submission.get("initial_device_display_name")
            device_id, access_token = yield self.registration_handler.register_device(
                registered_user_id, device_id, initial_display_name,
            )

            result = {
                "user_id": registered_user_id,
                "access_token": access_token,
                "home_server": self.hs.hostname,
            }
        else:
            user_id, access_token = (
                yield self.handlers.registration_handler.register(localpart=user)
            )

            device_id = login_submission.get("device_id")
            initial_display_name = login_submission.get("initial_device_display_name")
            device_id, access_token = yield self.registration_handler.register_device(
                registered_user_id, device_id, initial_display_name,
            )

            result = {
                "user_id": user_id,  # may have changed
                "access_token": access_token,
                "home_server": self.hs.hostname,
            }

        defer.returnValue(result)


class CasRedirectServlet(RestServlet):
    PATTERNS = client_path_patterns("/login/(cas|sso)/redirect")

    def __init__(self, hs):
        super(CasRedirectServlet, self).__init__()
        self.cas_server_url = hs.config.cas_server_url.encode('ascii')
        self.cas_service_url = hs.config.cas_service_url.encode('ascii')

    def on_GET(self, request):
        args = request.args
        if b"redirectUrl" not in args:
            return (400, "Redirect URL not specified for CAS auth")
        client_redirect_url_param = urllib.parse.urlencode({
            b"redirectUrl": args[b"redirectUrl"][0]
        }).encode('ascii')
        hs_redirect_url = (self.cas_service_url +
                           b"/_matrix/client/api/v1/login/cas/ticket")
        service_param = urllib.parse.urlencode({
            b"service": b"%s?%s" % (hs_redirect_url, client_redirect_url_param)
        }).encode('ascii')
        request.redirect(b"%s/login?%s" % (self.cas_server_url, service_param))
        finish_request(request)


class CasTicketServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns("/login/cas/ticket", releases=())

    def __init__(self, hs):
        super(CasTicketServlet, self).__init__(hs)
        self.cas_server_url = hs.config.cas_server_url
        self.cas_service_url = hs.config.cas_service_url
        self.cas_required_attributes = hs.config.cas_required_attributes
        self._sso_auth_handler = SSOAuthHandler(hs)

    @defer.inlineCallbacks
    def on_GET(self, request):
        client_redirect_url = parse_string(request, "redirectUrl", required=True)
        http_client = self.hs.get_simple_http_client()
        uri = self.cas_server_url + "/proxyValidate"
        args = {
            "ticket": parse_string(request, "ticket", required=True),
            "service": self.cas_service_url
        }
        try:
            body = yield http_client.get_raw(uri, args)
        except PartialDownloadError as pde:
            # Twisted raises this error if the connection is closed,
            # even if that's being used old-http style to signal end-of-data
            body = pde.response
        result = yield self.handle_cas_response(request, body, client_redirect_url)
        defer.returnValue(result)

    def handle_cas_response(self, request, cas_response_body, client_redirect_url):
        user, attributes = self.parse_cas_response(cas_response_body)

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
            user, request, client_redirect_url,
        )

    def parse_cas_response(self, cas_response_body):
        user = None
        attributes = {}
        try:
            root = ET.fromstring(cas_response_body)
            if not root.tag.endswith("serviceResponse"):
                raise Exception("root of CAS response is not serviceResponse")
            success = (root[0].tag.endswith("authenticationSuccess"))
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
            logger.error("Error parsing CAS response", exc_info=1)
            raise LoginError(401, "Invalid CAS response",
                             errcode=Codes.UNAUTHORIZED)
        if not success:
            raise LoginError(401, "Unsuccessful CAS response",
                             errcode=Codes.UNAUTHORIZED)
        return user, attributes


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

    @defer.inlineCallbacks
    def on_successful_auth(
        self, username, request, client_redirect_url,
        user_display_name=None,
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
        registered_user_id = yield self._auth_handler.check_user_exists(user_id)
        if not registered_user_id:
            registered_user_id, _ = (
                yield self._registration_handler.register(
                    localpart=localpart,
                    generate_token=False,
                    default_display_name=user_display_name,
                )
            )

        login_token = self._macaroon_gen.generate_short_term_login_token(
            registered_user_id
        )
        redirect_url = self._add_login_token_to_redirect_url(
            client_redirect_url, login_token
        )
        request.redirect(redirect_url)
        finish_request(request)

    @staticmethod
    def _add_login_token_to_redirect_url(url, token):
        url_parts = list(urllib.parse.urlparse(url))
        query = dict(urllib.parse.parse_qsl(url_parts[4]))
        query.update({"loginToken": token})
        url_parts[4] = urllib.parse.urlencode(query)
        return urllib.parse.urlunparse(url_parts)


def register_servlets(hs, http_server):
    LoginRestServlet(hs).register(http_server)
    if hs.config.cas_enabled:
        CasRedirectServlet(hs).register(http_server)
        CasTicketServlet(hs).register(http_server)
