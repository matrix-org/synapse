# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
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

from synapse.api.errors import SynapseError, LoginError, Codes
from synapse.types import UserID
from base import ClientV1RestServlet, client_path_patterns

import simplejson as json
import urllib
import urlparse

import logging
from saml2 import BINDING_HTTP_POST
from saml2 import config
from saml2.client import Saml2Client

import xml.etree.ElementTree as ET


logger = logging.getLogger(__name__)


class LoginRestServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns("/login$")
    PASS_TYPE = "m.login.password"
    SAML2_TYPE = "m.login.saml2"
    CAS_TYPE = "m.login.cas"
    TOKEN_TYPE = "m.login.token"

    def __init__(self, hs):
        super(LoginRestServlet, self).__init__(hs)
        self.idp_redirect_url = hs.config.saml2_idp_redirect_url
        self.password_enabled = hs.config.password_enabled
        self.saml2_enabled = hs.config.saml2_enabled
        self.cas_enabled = hs.config.cas_enabled
        self.cas_server_url = hs.config.cas_server_url
        self.cas_required_attributes = hs.config.cas_required_attributes
        self.servername = hs.config.server_name
        self.http_client = hs.get_simple_http_client()

    def on_GET(self, request):
        flows = []
        if self.saml2_enabled:
            flows.append({"type": LoginRestServlet.SAML2_TYPE})
        if self.cas_enabled:
            flows.append({"type": LoginRestServlet.CAS_TYPE})

            # While its valid for us to advertise this login type generally,
            # synapse currently only gives out these tokens as part of the
            # CAS login flow.
            # Generally we don't want to advertise login flows that clients
            # don't know how to implement, since they (currently) will always
            # fall back to the fallback API if they don't understand one of the
            # login flow types returned.
            flows.append({"type": LoginRestServlet.TOKEN_TYPE})
        if self.password_enabled:
            flows.append({"type": LoginRestServlet.PASS_TYPE})

        return (200, {"flows": flows})

    def on_OPTIONS(self, request):
        return (200, {})

    @defer.inlineCallbacks
    def on_POST(self, request):
        login_submission = _parse_json(request)
        try:
            if login_submission["type"] == LoginRestServlet.PASS_TYPE:
                if not self.password_enabled:
                    raise SynapseError(400, "Password login has been disabled.")

                result = yield self.do_password_login(login_submission)
                defer.returnValue(result)
            elif self.saml2_enabled and (login_submission["type"] ==
                                         LoginRestServlet.SAML2_TYPE):
                relay_state = ""
                if "relay_state" in login_submission:
                    relay_state = "&RelayState="+urllib.quote(
                                  login_submission["relay_state"])
                result = {
                    "uri": "%s%s" % (self.idp_redirect_url, relay_state)
                }
                defer.returnValue((200, result))
            # TODO Delete this after all CAS clients switch to token login instead
            elif self.cas_enabled and (login_submission["type"] ==
                                       LoginRestServlet.CAS_TYPE):
                uri = "%s/proxyValidate" % (self.cas_server_url,)
                args = {
                    "ticket": login_submission["ticket"],
                    "service": login_submission["service"]
                }
                body = yield self.http_client.get_raw(uri, args)
                result = yield self.do_cas_login(body)
                defer.returnValue(result)
            elif login_submission["type"] == LoginRestServlet.TOKEN_TYPE:
                result = yield self.do_token_login(login_submission)
                defer.returnValue(result)
            else:
                raise SynapseError(400, "Bad login type.")
        except KeyError:
            raise SynapseError(400, "Missing JSON keys.")

    @defer.inlineCallbacks
    def do_password_login(self, login_submission):
        if 'medium' in login_submission and 'address' in login_submission:
            user_id = yield self.hs.get_datastore().get_user_id_by_threepid(
                login_submission['medium'], login_submission['address']
            )
            if not user_id:
                raise LoginError(403, "", errcode=Codes.FORBIDDEN)
        else:
            user_id = login_submission['user']

        if not user_id.startswith('@'):
            user_id = UserID.create(
                user_id, self.hs.hostname
            ).to_string()

        auth_handler = self.handlers.auth_handler
        user_id, access_token, refresh_token = yield auth_handler.login_with_password(
            user_id=user_id,
            password=login_submission["password"])

        result = {
            "user_id": user_id,  # may have changed
            "access_token": access_token,
            "refresh_token": refresh_token,
            "home_server": self.hs.hostname,
        }

        defer.returnValue((200, result))

    @defer.inlineCallbacks
    def do_token_login(self, login_submission):
        token = login_submission['token']
        auth_handler = self.handlers.auth_handler
        user_id = (
            yield auth_handler.validate_short_term_login_token_and_get_user_id(token)
        )
        user_id, access_token, refresh_token = (
            yield auth_handler.get_login_tuple_for_user_id(user_id)
        )
        result = {
            "user_id": user_id,  # may have changed
            "access_token": access_token,
            "refresh_token": refresh_token,
            "home_server": self.hs.hostname,
        }

        defer.returnValue((200, result))

    # TODO Delete this after all CAS clients switch to token login instead
    @defer.inlineCallbacks
    def do_cas_login(self, cas_response_body):
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

        user_id = UserID.create(user, self.hs.hostname).to_string()
        auth_handler = self.handlers.auth_handler
        user_exists = yield auth_handler.does_user_exist(user_id)
        if user_exists:
            user_id, access_token, refresh_token = (
                yield auth_handler.get_login_tuple_for_user_id(user_id)
            )
            result = {
                "user_id": user_id,  # may have changed
                "access_token": access_token,
                "refresh_token": refresh_token,
                "home_server": self.hs.hostname,
            }

        else:
            user_id, access_token = (
                yield self.handlers.registration_handler.register(localpart=user)
            )
            result = {
                "user_id": user_id,  # may have changed
                "access_token": access_token,
                "home_server": self.hs.hostname,
            }

        defer.returnValue((200, result))

    # TODO Delete this after all CAS clients switch to token login instead
    def parse_cas_response(self, cas_response_body):
        root = ET.fromstring(cas_response_body)
        if not root.tag.endswith("serviceResponse"):
            raise LoginError(401, "Invalid CAS response", errcode=Codes.UNAUTHORIZED)
        if not root[0].tag.endswith("authenticationSuccess"):
            raise LoginError(401, "Unsuccessful CAS response", errcode=Codes.UNAUTHORIZED)
        for child in root[0]:
            if child.tag.endswith("user"):
                user = child.text
            if child.tag.endswith("attributes"):
                attributes = {}
                for attribute in child:
                    # ElementTree library expands the namespace in attribute tags
                    # to the full URL of the namespace.
                    # See (https://docs.python.org/2/library/xml.etree.elementtree.html)
                    # We don't care about namespace here and it will always be encased in
                    # curly braces, so we remove them.
                    if "}" in attribute.tag:
                        attributes[attribute.tag.split("}")[1]] = attribute.text
                    else:
                        attributes[attribute.tag] = attribute.text
        if user is None or attributes is None:
            raise LoginError(401, "Invalid CAS response", errcode=Codes.UNAUTHORIZED)

        return (user, attributes)


class SAML2RestServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns("/login/saml2", releases=())

    def __init__(self, hs):
        super(SAML2RestServlet, self).__init__(hs)
        self.sp_config = hs.config.saml2_config_path

    @defer.inlineCallbacks
    def on_POST(self, request):
        saml2_auth = None
        try:
            conf = config.SPConfig()
            conf.load_file(self.sp_config)
            SP = Saml2Client(conf)
            saml2_auth = SP.parse_authn_request_response(
                request.args['SAMLResponse'][0], BINDING_HTTP_POST)
        except Exception, e:        # Not authenticated
            logger.exception(e)
        if saml2_auth and saml2_auth.status_ok() and not saml2_auth.not_signed:
            username = saml2_auth.name_id.text
            handler = self.handlers.registration_handler
            (user_id, token) = yield handler.register_saml2(username)
            # Forward to the RelayState callback along with ava
            if 'RelayState' in request.args:
                request.redirect(urllib.unquote(
                                 request.args['RelayState'][0]) +
                                 '?status=authenticated&access_token=' +
                                 token + '&user_id=' + user_id + '&ava=' +
                                 urllib.quote(json.dumps(saml2_auth.ava)))
                request.finish()
                defer.returnValue(None)
            defer.returnValue((200, {"status": "authenticated",
                                     "user_id": user_id, "token": token,
                                     "ava": saml2_auth.ava}))
        elif 'RelayState' in request.args:
            request.redirect(urllib.unquote(
                             request.args['RelayState'][0]) +
                             '?status=not_authenticated')
            request.finish()
            defer.returnValue(None)
        defer.returnValue((200, {"status": "not_authenticated"}))


# TODO Delete this after all CAS clients switch to token login instead
class CasRestServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns("/login/cas", releases=())

    def __init__(self, hs):
        super(CasRestServlet, self).__init__(hs)
        self.cas_server_url = hs.config.cas_server_url

    def on_GET(self, request):
        return (200, {"serverUrl": self.cas_server_url})


class CasRedirectServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns("/login/cas/redirect", releases=())

    def __init__(self, hs):
        super(CasRedirectServlet, self).__init__(hs)
        self.cas_server_url = hs.config.cas_server_url
        self.cas_service_url = hs.config.cas_service_url

    def on_GET(self, request):
        args = request.args
        if "redirectUrl" not in args:
            return (400, "Redirect URL not specified for CAS auth")
        client_redirect_url_param = urllib.urlencode({
            "redirectUrl": args["redirectUrl"][0]
        })
        hs_redirect_url = self.cas_service_url + "/_matrix/client/api/v1/login/cas/ticket"
        service_param = urllib.urlencode({
            "service": "%s?%s" % (hs_redirect_url, client_redirect_url_param)
        })
        request.redirect("%s?%s" % (self.cas_server_url, service_param))
        request.finish()


class CasTicketServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns("/login/cas/ticket", releases=())

    def __init__(self, hs):
        super(CasTicketServlet, self).__init__(hs)
        self.cas_server_url = hs.config.cas_server_url
        self.cas_service_url = hs.config.cas_service_url
        self.cas_required_attributes = hs.config.cas_required_attributes

    @defer.inlineCallbacks
    def on_GET(self, request):
        client_redirect_url = request.args["redirectUrl"][0]
        http_client = self.hs.get_simple_http_client()
        uri = self.cas_server_url + "/proxyValidate"
        args = {
            "ticket": request.args["ticket"],
            "service": self.cas_service_url
        }
        body = yield http_client.get_raw(uri, args)
        result = yield self.handle_cas_response(request, body, client_redirect_url)
        defer.returnValue(result)

    @defer.inlineCallbacks
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

        user_id = UserID.create(user, self.hs.hostname).to_string()
        auth_handler = self.handlers.auth_handler
        user_exists = yield auth_handler.does_user_exist(user_id)
        if not user_exists:
            user_id, _ = (
                yield self.handlers.registration_handler.register(localpart=user)
            )

        login_token = auth_handler.generate_short_term_login_token(user_id)
        redirect_url = self.add_login_token_to_redirect_url(client_redirect_url,
                                                            login_token)
        request.redirect(redirect_url)
        request.finish()

    def add_login_token_to_redirect_url(self, url, token):
        url_parts = list(urlparse.urlparse(url))
        query = dict(urlparse.parse_qsl(url_parts[4]))
        query.update({"loginToken": token})
        url_parts[4] = urllib.urlencode(query)
        return urlparse.urlunparse(url_parts)

    def parse_cas_response(self, cas_response_body):
        root = ET.fromstring(cas_response_body)
        if not root.tag.endswith("serviceResponse"):
            raise LoginError(401, "Invalid CAS response", errcode=Codes.UNAUTHORIZED)
        if not root[0].tag.endswith("authenticationSuccess"):
            raise LoginError(401, "Unsuccessful CAS response", errcode=Codes.UNAUTHORIZED)
        for child in root[0]:
            if child.tag.endswith("user"):
                user = child.text
            if child.tag.endswith("attributes"):
                attributes = {}
                for attribute in child:
                    # ElementTree library expands the namespace in attribute tags
                    # to the full URL of the namespace.
                    # See (https://docs.python.org/2/library/xml.etree.elementtree.html)
                    # We don't care about namespace here and it will always be encased in
                    # curly braces, so we remove them.
                    if "}" in attribute.tag:
                        attributes[attribute.tag.split("}")[1]] = attribute.text
                    else:
                        attributes[attribute.tag] = attribute.text
        if user is None or attributes is None:
            raise LoginError(401, "Invalid CAS response", errcode=Codes.UNAUTHORIZED)

        return (user, attributes)


def _parse_json(request):
    try:
        content = json.loads(request.content.read())
        if type(content) != dict:
            raise SynapseError(400, "Content must be a JSON object.")
        return content
    except ValueError:
        raise SynapseError(400, "Content not JSON.")


def register_servlets(hs, http_server):
    LoginRestServlet(hs).register(http_server)
    if hs.config.saml2_enabled:
        SAML2RestServlet(hs).register(http_server)
    if hs.config.cas_enabled:
        CasRedirectServlet(hs).register(http_server)
        CasTicketServlet(hs).register(http_server)
        CasRestServlet(hs).register(http_server)
    # TODO PasswordResetRestServlet(hs).register(http_server)
