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
import gc
import hashlib
import hmac
import logging
import time

from mock import Mock

from canonicaljson import json

import twisted
import twisted.logger
from twisted.internet.defer import Deferred, succeed
from twisted.python.threadpool import ThreadPool
from twisted.trial import unittest

from synapse.api.constants import EventTypes
from synapse.config.homeserver import HomeServerConfig
from synapse.http.server import JsonResource
from synapse.http.site import SynapseRequest
from synapse.server import HomeServer
from synapse.types import Requester, UserID, create_requester
from synapse.util.logcontext import LoggingContext

from tests.server import get_clock, make_request, render, setup_test_homeserver
from tests.test_utils.logging_setup import setup_logging
from tests.utils import default_config, setupdb

setupdb()
setup_logging()


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

        level = getattr(method, "loglevel", getattr(self, "loglevel", None))

        @around(self)
        def setUp(orig):
            # enable debugging of delayed calls - this means that we get a
            # traceback when a unit test exits leaving things on the reactor.
            twisted.internet.base.DelayedCall.debug = True

            # if we're not starting in the sentinel logcontext, then to be honest
            # all future bets are off.
            if LoggingContext.current_context() is not LoggingContext.sentinel:
                self.fail(
                    "Test starting with non-sentinel logging context %s"
                    % (LoggingContext.current_context(),)
                )

            old_level = logging.getLogger().level
            if level is not None and old_level != level:

                @around(self)
                def tearDown(orig):
                    ret = orig()
                    logging.getLogger().setLevel(old_level)
                    return ret

                logging.getLogger().setLevel(level)

            return orig()

        @around(self)
        def tearDown(orig):
            ret = orig()
            # force a GC to workaround problems with deferreds leaking logcontexts when
            # they are GCed (see the logcontext docs)
            gc.collect()
            LoggingContext.set_current_context(LoggingContext.sentinel)

            return ret

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


def INFO(target):
    """A decorator to set the .loglevel attribute to logging.INFO.
    Can apply to either a TestCase or an individual test method."""
    target.loglevel = logging.INFO
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
    needs_threadpool = False

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
        self.resource = self.create_test_json_resource()

        from tests.rest.client.v1.utils import RestHelper

        self.helper = RestHelper(self.hs, self.resource, getattr(self, "user_id", None))

        if hasattr(self, "user_id"):
            if self.hijack_auth:

                def get_user_by_access_token(token=None, allow_guest=False):
                    return succeed(
                        {
                            "user": UserID.from_string(self.helper.auth_user_id),
                            "token_id": 1,
                            "is_guest": False,
                        }
                    )

                def get_user_by_req(request, allow_guest=False, rights="access"):
                    return succeed(
                        create_requester(
                            UserID.from_string(self.helper.auth_user_id), 1, False, None
                        )
                    )

                self.hs.get_auth().get_user_by_req = get_user_by_req
                self.hs.get_auth().get_user_by_access_token = get_user_by_access_token
                self.hs.get_auth().get_access_token_from_request = Mock(
                    return_value="1234"
                )

        if self.needs_threadpool:
            self.reactor.threadpool = ThreadPool()
            self.addCleanup(self.reactor.threadpool.stop)
            self.reactor.threadpool.start()

        if hasattr(self, "prepare"):
            self.prepare(self.reactor, self.clock, self.hs)

    def wait_on_thread(self, deferred, timeout=10):
        """
        Wait until a Deferred is done, where it's waiting on a real thread.
        """
        start_time = time.time()

        while not deferred.called:
            if start_time + timeout < time.time():
                raise ValueError("Timed out waiting for threadpool")
            self.reactor.advance(0.01)
            time.sleep(0.01)

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

    def create_test_json_resource(self):
        """
        Create a test JsonResource, with the relevant servlets registerd to it

        The default implementation calls each function in `servlets` to do the
        registration.

        Returns:
            JsonResource:
        """
        resource = JsonResource(self.hs)

        for servlet in self.servlets:
            servlet(self.hs, resource)

        return resource

    def default_config(self, name="test"):
        """
        Get a default HomeServer config dict.

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
        self,
        method,
        path,
        content=b"",
        access_token=None,
        request=SynapseRequest,
        shorthand=True,
        federation_auth_origin=None,
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
            shorthand: Whether to try and be helpful and prefix the given URL
            with the usual REST API path, if it doesn't contain it.
            federation_auth_origin (bytes|None): if set to not-None, we will add a fake
                Authorization header pretenting to be the given server name.

        Returns:
            Tuple[synapse.http.site.SynapseRequest, channel]
        """
        if isinstance(content, dict):
            content = json.dumps(content).encode("utf8")

        return make_request(
            self.reactor,
            method,
            path,
            content,
            access_token,
            request,
            shorthand,
            federation_auth_origin,
        )

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
        if "config" not in kwargs:
            config = self.default_config()
        else:
            config = kwargs["config"]

        # Parse the config from a config dict into a HomeServerConfig
        config_obj = HomeServerConfig()
        config_obj.parse_config_dict(config, "", "")
        kwargs["config"] = config_obj

        hs = setup_test_homeserver(self.addCleanup, *args, **kwargs)
        stor = hs.get_datastore()

        # Run the database background updates.
        if hasattr(stor, "do_next_background_update"):
            while not self.get_success(stor.has_completed_background_updates()):
                self.get_success(stor.do_next_background_update(1))

        return hs

    def pump(self, by=0.0):
        """
        Pump the reactor enough that Deferreds will fire.
        """
        self.reactor.pump([by] * 100)

    def get_success(self, d, by=0.0):
        if not isinstance(d, Deferred):
            return d
        self.pump(by=by)
        return self.successResultOf(d)

    def get_failure(self, d, exc):
        """
        Run a Deferred and get a Failure from it. The failure must be of the type `exc`.
        """
        if not isinstance(d, Deferred):
            return d
        self.pump()
        return self.failureResultOf(d, exc)

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
        self.hs.config.registration_shared_secret = "shared"

        # Create the user
        request, channel = self.make_request("GET", "/_matrix/client/r0/admin/register")
        self.render(request)
        nonce = channel.json_body["nonce"]

        want_mac = hmac.new(key=b"shared", digestmod=hashlib.sha1)
        nonce_str = b"\x00".join([username.encode("utf8"), password.encode("utf8")])
        if admin:
            nonce_str += b"\x00admin"
        else:
            nonce_str += b"\x00notadmin"

        want_mac.update(nonce.encode("ascii") + b"\x00" + nonce_str)
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
            "POST", "/_matrix/client/r0/admin/register", body.encode("utf8")
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
            "POST", "/_matrix/client/r0/login", json.dumps(body).encode("utf8")
        )
        self.render(request)
        self.assertEqual(channel.code, 200, channel.result)

        access_token = channel.json_body["access_token"]
        return access_token

    def create_and_send_event(
        self, room_id, user, soft_failed=False, prev_event_ids=None
    ):
        """
        Create and send an event.

        Args:
            soft_failed (bool): Whether to create a soft failed event or not
            prev_event_ids (list[str]|None): Explicitly set the prev events,
                or if None just use the default

        Returns:
            str: The new event's ID.
        """
        event_creator = self.hs.get_event_creation_handler()
        secrets = self.hs.get_secrets()
        requester = Requester(user, None, False, None, None)

        prev_events_and_hashes = None
        if prev_event_ids:
            prev_events_and_hashes = [[p, {}, 0] for p in prev_event_ids]

        event, context = self.get_success(
            event_creator.create_event(
                requester,
                {
                    "type": EventTypes.Message,
                    "room_id": room_id,
                    "sender": user.to_string(),
                    "content": {"body": secrets.token_hex(), "msgtype": "m.text"},
                },
                prev_events_and_hashes=prev_events_and_hashes,
            )
        )

        if soft_failed:
            event.internal_metadata.soft_failed = True

        self.get_success(event_creator.send_nonmember_event(requester, event, context))

        return event.event_id

    def add_extremity(self, room_id, event_id):
        """
        Add the given event as an extremity to the room.
        """
        self.get_success(
            self.hs.get_datastore()._simple_insert(
                table="event_forward_extremities",
                values={"room_id": room_id, "event_id": event_id},
                desc="test_add_extremity",
            )
        )

        self.hs.get_datastore().get_latest_event_ids_in_room.invalidate((room_id,))

    def attempt_wrong_password_login(self, username, password):
        """Attempts to login as the user with the given password, asserting
        that the attempt *fails*.
        """
        body = {"type": "m.login.password", "user": username, "password": password}

        request, channel = self.make_request(
            "POST", "/_matrix/client/r0/login", json.dumps(body).encode("utf8")
        )
        self.render(request)
        self.assertEqual(channel.code, 403, channel.result)
