# -*- coding: utf-8 -*-
# Copyright 2019 New Vector Ltd
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
import re

import jinja2

from twisted.internet import defer

from synapse.api.errors import ThreepidValidationError
from synapse.http.server import finish_request
from synapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_json_object_from_request,
    parse_string,
)

logger = logging.getLogger(__name__)


def make_identity_path_pattern(path_regex):
    prefix = "/_matrix/identity/api/v1"
    return [re.compile(prefix + path_regex)]


class ThreepidSubmitTokenServlet(RestServlet):
    """Servlet which will handle 3PID token validation"""
    PATTERNS = make_identity_path_pattern("/validate/(email|msisdn)/submitToken/*$")

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        self.hs = hs
        self.auth = hs.get_auth()
        self.config = hs.config
        self.clock = hs.get_clock()
        self.datastore = hs.get_datastore()

    @defer.inlineCallbacks
    def on_GET(self, request):
        sid = parse_string(request, "sid")
        client_secret = parse_string(request, "client_secret")
        token = parse_string(request, "token")

        # Attempt to validate a 3PID sesssion
        try:
            # Mark the session as valid
            next_link = yield self.datastore.validate_threepid_session(
                sid,
                client_secret,
                token,
                self.clock.time_msec(),
            )

            # Delete associated session tokens from the db as we have no
            # further use for them
            yield self.datastore.delete_threepid_tokens(sid)

            # Perform a 302 redirect if next_link is set
            if next_link:
                if next_link.startswith("file:///"):
                    logger.warn(
                        "Not redirecting to next_link as it is a local file: address"
                    )
                else:
                    request.setResponseCode(302)
                    request.setHeader("Location", next_link)
                    finish_request(request)
                    defer.returnValue(None)

            # Otherwise show the success template
            html = self.config.email_password_reset_success_html_content
            request.setResponseCode(200)
        except ThreepidValidationError as e:
            # Show a failure page with a reason
            html = self.load_jinja2_template(
                self.config.email_template_dir,
                self.config.email_password_reset_failure_template,
                template_vars={
                    "failure_reason": e.msg,
                }
            )
            request.setResponseCode(e.code)

        request.write(html.encode('utf-8'))
        finish_request(request)
        defer.returnValue(None)

    def load_jinja2_template(self, template_dir, template_filename, template_vars):
        """Loads a jinja2 template with variables to insert

        Args:
            template_dir (str): The directory where templates are stored
            template_filename (str): The name of the template in the template_dir
            template_vars (Dict): Dictionary of keys in the template
                alongside their values to insert

        Returns:
            str containing the contents of the rendered template
        """
        loader = jinja2.FileSystemLoader(template_dir)
        env = jinja2.Environment(loader=loader)

        template = env.get_template(template_filename)
        return template.render(**template_vars)

    @defer.inlineCallbacks
    def on_POST(self, request):
        body = parse_json_object_from_request(request)
        assert_params_in_dict(body, [
            'sid', 'client_secret', 'token',
        ])

        valid, _ = yield self.datastore.validate_threepid_validation_token(
            body['sid'],
            body['client_secret'],
            body['token'],
            self.clock.time_msec(),
        )
        response_code = 200 if valid else 400

        defer.returnValue((response_code, {"success": valid}))
