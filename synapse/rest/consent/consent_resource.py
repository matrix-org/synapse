# -*- coding: utf-8 -*-
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

import hmac
import logging
from hashlib import sha256
from os import path

from six.moves import http_client

import jinja2
from jinja2 import TemplateNotFound

from twisted.internet import defer
from twisted.web.resource import Resource
from twisted.web.server import NOT_DONE_YET

from synapse.api.errors import NotFoundError, StoreError, SynapseError
from synapse.config import ConfigError
from synapse.http.server import finish_request, wrap_html_request_handler
from synapse.http.servlet import parse_string
from synapse.types import UserID

# language to use for the templates. TODO: figure this out from Accept-Language
TEMPLATE_LANGUAGE = "en"

logger = logging.getLogger(__name__)

# use hmac.compare_digest if we have it (python 2.7.7), else just use equality
if hasattr(hmac, "compare_digest"):
    compare_digest = hmac.compare_digest
else:
    def compare_digest(a, b):
        return a == b


class ConsentResource(Resource):
    """A twisted Resource to display a privacy policy and gather consent to it

    When accessed via GET, returns the privacy policy via a template.

    When accessed via POST, records the user's consent in the database and
    displays a success page.

    The config should include a template_dir setting which contains templates
    for the HTML. The directory should contain one subdirectory per language
    (eg, 'en', 'fr'), and each language directory should contain the policy
    document (named as '<version>.html') and a success page (success.html).

    Both forms take a set of parameters from the browser. For the POST form,
    these are normally sent as form parameters (but may be query-params); for
    GET requests they must be query params. These are:

        u: the complete mxid, or the localpart of the user giving their
           consent. Required for both GET (where it is used as an input to the
           template) and for POST (where it is used to find the row in the db
           to update).

        h: hmac_sha256(secret, u), where 'secret' is the privacy_secret in the
           config file. If it doesn't match, the request is 403ed.

        v: the version of the privacy policy being agreed to.

           For GET: optional, and defaults to whatever was set in the config
           file. Used to choose the version of the policy to pick from the
           templates directory.

           For POST: required; gives the value to be recorded in the database
           against the user.
    """
    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer): homeserver
        """
        Resource.__init__(self)

        self.hs = hs
        self.store = hs.get_datastore()
        self.registration_handler = hs.get_registration_handler()

        # this is required by the request_handler wrapper
        self.clock = hs.get_clock()

        self._default_consent_version = hs.config.user_consent_version
        if self._default_consent_version is None:
            raise ConfigError(
                "Consent resource is enabled but user_consent section is "
                "missing in config file.",
            )

        consent_template_directory = hs.config.user_consent_template_dir

        loader = jinja2.FileSystemLoader(consent_template_directory)
        self._jinja_env = jinja2.Environment(
            loader=loader,
            autoescape=jinja2.select_autoescape(['html', 'htm', 'xml']),
        )

        if hs.config.form_secret is None:
            raise ConfigError(
                "Consent resource is enabled but form_secret is not set in "
                "config file. It should be set to an arbitrary secret string.",
            )

        self._hmac_secret = hs.config.form_secret.encode("utf-8")

    def render_GET(self, request):
        self._async_render_GET(request)
        return NOT_DONE_YET

    @wrap_html_request_handler
    @defer.inlineCallbacks
    def _async_render_GET(self, request):
        """
        Args:
            request (twisted.web.http.Request):
        """

        version = parse_string(request, "v", default=self._default_consent_version)
        username = parse_string(request, "u", required=False, default="")
        userhmac = None
        has_consented = False
        public_version = username == ""
        if not public_version:
            userhmac_bytes = parse_string(request, "h", required=True, encoding=None)

            self._check_hash(username, userhmac_bytes)

            if username.startswith('@'):
                qualified_user_id = username
            else:
                qualified_user_id = UserID(username, self.hs.hostname).to_string()

            u = yield self.store.get_user_by_id(qualified_user_id)
            if u is None:
                raise NotFoundError("Unknown user")

            has_consented = u["consent_version"] == version
            userhmac = userhmac_bytes.decode("ascii")

        try:
            self._render_template(
                request, "%s.html" % (version,),
                user=username,
                userhmac=userhmac,
                version=version,
                has_consented=has_consented,
                public_version=public_version,
            )
        except TemplateNotFound:
            raise NotFoundError("Unknown policy version")

    def render_POST(self, request):
        self._async_render_POST(request)
        return NOT_DONE_YET

    @wrap_html_request_handler
    @defer.inlineCallbacks
    def _async_render_POST(self, request):
        """
        Args:
            request (twisted.web.http.Request):
        """
        version = parse_string(request, "v", required=True)
        username = parse_string(request, "u", required=True)
        userhmac = parse_string(request, "h", required=True, encoding=None)

        self._check_hash(username, userhmac)

        if username.startswith('@'):
            qualified_user_id = username
        else:
            qualified_user_id = UserID(username, self.hs.hostname).to_string()

        try:
            yield self.store.user_set_consent_version(qualified_user_id, version)
        except StoreError as e:
            if e.code != 404:
                raise
            raise NotFoundError("Unknown user")
        yield self.registration_handler.post_consent_actions(qualified_user_id)

        try:
            self._render_template(request, "success.html")
        except TemplateNotFound:
            raise NotFoundError("success.html not found")

    def _render_template(self, request, template_name, **template_args):
        # get_template checks for ".." so we don't need to worry too much
        # about path traversal here.
        template_html = self._jinja_env.get_template(
            path.join(TEMPLATE_LANGUAGE, template_name)
        )
        html_bytes = template_html.render(**template_args).encode("utf8")

        request.setHeader(b"Content-Type", b"text/html; charset=utf-8")
        request.setHeader(b"Content-Length", b"%i" % len(html_bytes))
        request.write(html_bytes)
        finish_request(request)

    def _check_hash(self, userid, userhmac):
        """
        Args:
            userid (unicode):
            userhmac (bytes):

        Raises:
              SynapseError if the hash doesn't match

        """
        want_mac = hmac.new(
            key=self._hmac_secret,
            msg=userid.encode('utf-8'),
            digestmod=sha256,
        ).hexdigest().encode('ascii')

        if not compare_digest(want_mac, userhmac):
            raise SynapseError(http_client.FORBIDDEN, "HMAC incorrect")
