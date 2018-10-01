# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018 New Vector
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

from mock import Mock

from canonicaljson import json

import twisted
import twisted.logger
from twisted.internet.defer import Deferred
from twisted.trial import unittest

from synapse.http.server import JsonResource
from synapse.http.site import SynapseRequest
from synapse.server import HomeServer
from synapse.types import UserID, create_requester
from synapse.util.logcontext import LoggingContextFilter

from tests.server import get_clock, make_request, render, setup_test_homeserver
from tests.utils import default_config

# Set up putting Synapse's logs into Trial's.
rootLogger = logging.getLogger()

log_format = (
    "%(asctime)s - %(name)s - %(lineno)d - %(levelname)s - %(request)s - %(message)s"
)


class ToTwistedHandler(logging.Handler):
    tx_log = twisted.logger.Logger()

    def emit(self, record):
        log_entry = self.format(record)
        log_level = record.levelname.lower().replace('warning', 'warn')
        self.tx_log.emit(
            twisted.logger.LogLevel.levelWithName(log_level),
            log_entry.replace("{", r"(").replace("}", r")"),
        )


handler = ToTwistedHandler()
formatter = logging.Formatter(log_format)
handler.setFormatter(formatter)
handler.addFilter(LoggingContextFilter(request=""))
rootLogger.addHandler(handler)


def around(target):
    """A CLOS-style 'around' modifier, which wraps the original method of the
    given instance with another piece of code.

    @around(self)
    def method_name(orig, *args, **kwargs):
        return orig(*args, **kwargs)
    """

    def _around(code):
        name = code.__name__
        orig = getattr(target, name)

        def new(*args, **kwargs):
            return code(orig, *args, **kwargs)

        setattr(target, name, new)

    return _around


class TestCase(unittest.TestCase):
    """A subclass of twisted.trial's TestCase which looks for 'loglevel'
    attributes on both itself and its individual test methods, to override the
    root logger's logging level while that test (case|method) runs."""

    def __init__(self, methodName, *args, **kwargs):
        super(TestCase, self).__init__(methodName, *args, **kwargs)

        method = getattr(self, methodName)

        level = getattr(method, "loglevel", getattr(self, "loglevel", logging.ERROR))

        @around(self)
        def setUp(orig):
            # enable debugging of delayed calls - this means that we get a
            # traceback when a unit test exits leaving things on the reactor.
            twisted.internet.base.DelayedCall.debug = True

            old_level = logging.getLogger().level

            if old_level != level:

                @around(self)
                def tearDown(orig):
                    ret = orig()
                    logging.getLogger().setLevel(old_level)
                    return ret

            logging.getLogger().setLevel(level)
            return orig()

    def assertObjectHasAttributes(self, attrs, obj):
        """Asserts that the given object has each of the attributes given, and
        that the value of each matches according to assertEquals."""
        for (key, value) in attrs.items():
            if not hasattr(obj, key):
                raise AssertionError("Expected obj to have a '.%s'" % key)
            try:
                self.assertEquals(attrs[key], getattr(obj, key))
            except AssertionError as e:
                raise (type(e))(e.message + " for '.%s'" % key)

    def assert_dict(self, required, actual):
        """Does a partial assert of a dict.

        Args:
            required (dict): The keys and value which MUST be in 'actual'.
            actual (dict): The test result. Extra keys will not be checked.
        """
        for key in required:
            self.assertEquals(
                required[key], actual[key], msg="%s mismatch. %s" % (key, actual)
            )


def DEBUG(target):
    """A decorator to set the .loglevel attribute to logging.DEBUG.
    Can apply to either a TestCase or an individual test method."""
    target.loglevel = logging.DEBUG
    return target


class HomeserverTestCase(TestCase):
    """
    A base TestCase that reduces boilerplate for HomeServer-using test cases.

    Attributes:
        servlets (list[function]): List of servlet registration function.
        user_id (str): The user ID to assume if auth is hijacked.
        hijack_auth (bool): Whether to hijack auth to return the user specified
        in user_id.
    """

    servlets = []
    hijack_auth = True

    def setUp(self):
        """
        Set up the TestCase by calling the homeserver constructor, optionally
        hijacking the authentication system to return a fixed user, and then
        calling the prepare function.
        """
        self.reactor, self.clock = get_clock()
        self._hs_args = {"clock": self.clock, "reactor": self.reactor}
        self.hs = self.make_homeserver(self.reactor, self.clock)

        if self.hs is None:
            raise Exception("No homeserver returned from make_homeserver.")

        if not isinstance(self.hs, HomeServer):
            raise Exception("A homeserver wasn't returned, but %r" % (self.hs,))

        # Register the resources
        self.resource = JsonResource(self.hs)

        for servlet in self.servlets:
            servlet(self.hs, self.resource)

        if hasattr(self, "user_id"):
            from tests.rest.client.v1.utils import RestHelper

            self.helper = RestHelper(self.hs, self.resource, self.user_id)

            if self.hijack_auth:

                def get_user_by_access_token(token=None, allow_guest=False):
                    return {
                        "user": UserID.from_string(self.helper.auth_user_id),
                        "token_id": 1,
                        "is_guest": False,
                    }

                def get_user_by_req(request, allow_guest=False, rights="access"):
                    return create_requester(
                        UserID.from_string(self.helper.auth_user_id), 1, False, None
                    )

                self.hs.get_auth().get_user_by_req = get_user_by_req
                self.hs.get_auth().get_user_by_access_token = get_user_by_access_token
                self.hs.get_auth().get_access_token_from_request = Mock(
                    return_value="1234"
                )

        if hasattr(self, "prepare"):
            self.prepare(self.reactor, self.clock, self.hs)

    def make_homeserver(self, reactor, clock):
        """
        Make and return a homeserver.

        Args:
            reactor: A Twisted Reactor, or something that pretends to be one.
            clock (synapse.util.Clock): The Clock, associated with the reactor.

        Returns:
            A homeserver (synapse.server.HomeServer) suitable for testing.

        Function to be overridden in subclasses.
        """
        hs = self.setup_test_homeserver()
        return hs

    def default_config(self, name="test"):
        """
        Get a default HomeServer config object.

        Args:
            name (str): The homeserver name/domain.
        """
        return default_config(name)

    def prepare(self, reactor, clock, homeserver):
        """
        Prepare for the test.  This involves things like mocking out parts of
        the homeserver, or building test data common across the whole test
        suite.

        Args:
            reactor: A Twisted Reactor, or something that pretends to be one.
            clock (synapse.util.Clock): The Clock, associated with the reactor.
            homeserver (synapse.server.HomeServer): The HomeServer to test
            against.

        Function to optionally be overridden in subclasses.
        """

    def make_request(
        self, method, path, content=b"", access_token=None, request=SynapseRequest
    ):
        """
        Create a SynapseRequest at the path using the method and containing the
        given content.

        Args:
            method (bytes/unicode): The HTTP request method ("verb").
            path (bytes/unicode): The HTTP path, suitably URL encoded (e.g.
            escaped UTF-8 & spaces and such).
            content (bytes or dict): The body of the request. JSON-encoded, if
            a dict.

        Returns:
            A synapse.http.site.SynapseRequest.
        """
        if isinstance(content, dict):
            content = json.dumps(content).encode('utf8')

        return make_request(method, path, content, access_token, request)

    def render(self, request):
        """
        Render a request against the resources registered by the test class's
        servlets.

        Args:
            request (synapse.http.site.SynapseRequest): The request to render.
        """
        render(request, self.resource, self.reactor)

    def setup_test_homeserver(self, *args, **kwargs):
        """
        Set up the test homeserver, meant to be called by the overridable
        make_homeserver. It automatically passes through the test class's
        clock & reactor.

        Args:
            See tests.utils.setup_test_homeserver.

        Returns:
            synapse.server.HomeServer
        """
        kwargs = dict(kwargs)
        kwargs.update(self._hs_args)
        return setup_test_homeserver(self.addCleanup, *args, **kwargs)

    def pump(self, by=0.0):
        """
        Pump the reactor enough that Deferreds will fire.
        """
        self.reactor.pump([by] * 100)

    def get_success(self, d):
        if not isinstance(d, Deferred):
            return d
        self.pump()
        return self.successResultOf(d)

    def register_user(self, username, password, admin=False):
        """
        Register a user. Requires the Admin API be registered.

        Args:
            username (bytes/unicode): The user part of the new user.
            password (bytes/unicode): The password of the new user.
            admin (bool): Whether the user should be created as an admin
            or not.

        Returns:
            The MXID of the new user (unicode).
        """
        self.hs.config.registration_shared_secret = u"shared"

        # Create the user
        request, channel = self.make_request("GET", "/_matrix/client/r0/admin/register")
        self.render(request)
        nonce = channel.json_body["nonce"]

        want_mac = hmac.new(key=b"shared", digestmod=hashlib.sha1)
        nonce_str = b"\x00".join([username.encode('utf8'), password.encode('utf8')])
        if admin:
            nonce_str += b"\x00admin"
        else:
            nonce_str += b"\x00notadmin"
        want_mac.update(nonce.encode('ascii') + b"\x00" + nonce_str)
        want_mac = want_mac.hexdigest()

        body = json.dumps(
            {
                "nonce": nonce,
                "username": username,
                "password": password,
                "admin": admin,
                "mac": want_mac,
            }
        )
        request, channel = self.make_request(
            "POST", "/_matrix/client/r0/admin/register", body.encode('utf8')
        )
        self.render(request)
        self.assertEqual(channel.code, 200)

        user_id = channel.json_body["user_id"]
        return user_id

    def login(self, username, password, device_id=None):
        """
        Log in a user, and get an access token. Requires the Login API be
        registered.

        """
        body = {"type": "m.login.password", "user": username, "password": password}
        if device_id:
            body["device_id"] = device_id

        request, channel = self.make_request(
            "POST", "/_matrix/client/r0/login", json.dumps(body).encode('utf8')
        )
        self.render(request)
        self.assertEqual(channel.code, 200)

        access_token = channel.json_body["access_token"].encode('ascii')
        return access_token
