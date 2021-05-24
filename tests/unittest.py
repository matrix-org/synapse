# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018 New Vector
# Copyright 2019 Matrix.org Federation C.I.C
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
import inspect
import logging
import secrets
import time
from typing import Callable, Dict, Iterable, Optional, Tuple, Type, TypeVar, Union
from unittest.mock import Mock, patch

from canonicaljson import json

from twisted.internet.defer import Deferred, ensureDeferred, succeed
from twisted.python.failure import Failure
from twisted.python.threadpool import ThreadPool
from twisted.trial import unittest
from twisted.web.resource import Resource

from synapse import events
from synapse.api.constants import EventTypes, Membership
from synapse.config.homeserver import HomeServerConfig
from synapse.config.ratelimiting import FederationRateLimitConfig
from synapse.federation.transport import server as federation_server
from synapse.http.server import JsonResource
from synapse.http.site import SynapseRequest, SynapseSite
from synapse.logging.context import (
    SENTINEL_CONTEXT,
    LoggingContext,
    current_context,
    set_current_context,
)
from synapse.server import HomeServer
from synapse.types import UserID, create_requester
from synapse.util.httpresourcetree import create_resource_tree
from synapse.util.ratelimitutils import FederationRateLimiter

from tests.server import FakeChannel, get_clock, make_request, setup_test_homeserver
from tests.test_utils import event_injection, setup_awaitable_errors
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


T = TypeVar("T")


class TestCase(unittest.TestCase):
    """A subclass of twisted.trial's TestCase which looks for 'loglevel'
    attributes on both itself and its individual test methods, to override the
    root logger's logging level while that test (case|method) runs."""

    def __init__(self, methodName, *args, **kwargs):
        super().__init__(methodName, *args, **kwargs)

        method = getattr(self, methodName)

        level = getattr(method, "loglevel", getattr(self, "loglevel", None))

        @around(self)
        def setUp(orig):
            # if we're not starting in the sentinel logcontext, then to be honest
            # all future bets are off.
            if current_context():
                self.fail(
                    "Test starting with non-sentinel logging context %s"
                    % (current_context(),)
                )

            old_level = logging.getLogger().level
            if level is not None and old_level != level:

                @around(self)
                def tearDown(orig):
                    ret = orig()
                    logging.getLogger().setLevel(old_level)
                    return ret

                logging.getLogger().setLevel(level)

            # Trial messes with the warnings configuration, thus this has to be
            # done in the context of an individual TestCase.
            self.addCleanup(setup_awaitable_errors())

            return orig()

        @around(self)
        def tearDown(orig):
            ret = orig()
            # force a GC to workaround problems with deferreds leaking logcontexts when
            # they are GCed (see the logcontext docs)
            gc.collect()
            set_current_context(SENTINEL_CONTEXT)

            return ret

    def assertObjectHasAttributes(self, attrs, obj):
        """Asserts that the given object has each of the attributes given, and
        that the value of each matches according to assertEquals."""
        for key in attrs.keys():
            if not hasattr(obj, key):
                raise AssertionError("Expected obj to have a '.%s'" % key)
            try:
                self.assertEquals(attrs[key], getattr(obj, key))
            except AssertionError as e:
                raise (type(e))("Assert error for '.{}':".format(key)) from e

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


def logcontext_clean(target):
    """A decorator which marks the TestCase or method as 'logcontext_clean'

    ... ie, any logcontext errors should cause a test failure
    """

    def logcontext_error(msg):
        raise AssertionError("logcontext error: %s" % (msg))

    patcher = patch("synapse.logging.context.logcontext_error", new=logcontext_error)
    return patcher(target)


class HomeserverTestCase(TestCase):
    """
    A base TestCase that reduces boilerplate for HomeServer-using test cases.

    Defines a setUp method which creates a mock reactor, and instantiates a homeserver
    running on that reactor.

    There are various hooks for modifying the way that the homeserver is instantiated:

    * override make_homeserver, for example by making it pass different parameters into
      setup_test_homeserver.

    * override default_config, to return a modified configuration dictionary for use
      by setup_test_homeserver.

    * On a per-test basis, you can use the @override_config decorator to give a
      dictionary containing additional configuration settings to be added to the basic
      config dict.

    Attributes:
        servlets (list[function]): List of servlet registration function.
        user_id (str): The user ID to assume if auth is hijacked.
        hijack_auth (bool): Whether to hijack auth to return the user specified
        in user_id.
    """

    servlets = []
    hijack_auth = True
    needs_threadpool = False

    def __init__(self, methodName, *args, **kwargs):
        super().__init__(methodName, *args, **kwargs)

        # see if we have any additional config for this test
        method = getattr(self, methodName)
        self._extra_config = getattr(method, "_extra_config", None)

    def setUp(self):
        """
        Set up the TestCase by calling the homeserver constructor, optionally
        hijacking the authentication system to return a fixed user, and then
        calling the prepare function.
        """
        self.reactor, self.clock = get_clock()
        self._hs_args = {"clock": self.clock, "reactor": self.reactor}
        self.hs = self.make_homeserver(self.reactor, self.clock)

        # Honour the `use_frozen_dicts` config option. We have to do this
        # manually because this is taken care of in the app `start` code, which
        # we don't run. Plus we want to reset it on tearDown.
        events.USE_FROZEN_DICTS = self.hs.config.use_frozen_dicts

        if self.hs is None:
            raise Exception("No homeserver returned from make_homeserver.")

        if not isinstance(self.hs, HomeServer):
            raise Exception("A homeserver wasn't returned, but %r" % (self.hs,))

        # create the root resource, and a site to wrap it.
        self.resource = self.create_test_resource()
        self.site = SynapseSite(
            logger_name="synapse.access.http.fake",
            site_tag=self.hs.config.server.server_name,
            config=self.hs.config.server.listeners[0],
            resource=self.resource,
            server_version_string="1",
            max_request_body_size=1234,
            reactor=self.reactor,
        )

        from tests.rest.client.v1.utils import RestHelper

        self.helper = RestHelper(self.hs, self.site, getattr(self, "user_id", None))

        if hasattr(self, "user_id"):
            if self.hijack_auth:

                # We need a valid token ID to satisfy foreign key constraints.
                token_id = self.get_success(
                    self.hs.get_datastore().add_access_token_to_user(
                        self.helper.auth_user_id,
                        "some_fake_token",
                        None,
                        None,
                    )
                )

                async def get_user_by_access_token(token=None, allow_guest=False):
                    return {
                        "user": UserID.from_string(self.helper.auth_user_id),
                        "token_id": token_id,
                        "is_guest": False,
                    }

                async def get_user_by_req(request, allow_guest=False, rights="access"):
                    return create_requester(
                        UserID.from_string(self.helper.auth_user_id),
                        token_id,
                        False,
                        False,
                        None,
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

    def tearDown(self):
        # Reset to not use frozen dicts.
        events.USE_FROZEN_DICTS = False

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

    def create_test_resource(self) -> Resource:
        """
        Create a the root resource for the test server.

        The default calls `self.create_resource_dict` and builds the resultant dict
        into a tree.
        """
        root_resource = Resource()
        create_resource_tree(self.create_resource_dict(), root_resource)
        return root_resource

    def create_resource_dict(self) -> Dict[str, Resource]:
        """Create a resource tree for the test server

        A resource tree is a mapping from path to twisted.web.resource.

        The default implementation creates a JsonResource and calls each function in
        `servlets` to register servlets against it.
        """
        servlet_resource = JsonResource(self.hs)
        for servlet in self.servlets:
            servlet(self.hs, servlet_resource)
        return {
            "/_matrix/client": servlet_resource,
            "/_synapse/admin": servlet_resource,
        }

    def default_config(self):
        """
        Get a default HomeServer config dict.
        """
        config = default_config("test")

        # apply any additional config which was specified via the override_config
        # decorator.
        if self._extra_config is not None:
            config.update(self._extra_config)

        return config

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
        method: Union[bytes, str],
        path: Union[bytes, str],
        content: Union[bytes, dict] = b"",
        access_token: Optional[str] = None,
        request: Type[T] = SynapseRequest,
        shorthand: bool = True,
        federation_auth_origin: str = None,
        content_is_form: bool = False,
        await_result: bool = True,
        custom_headers: Optional[
            Iterable[Tuple[Union[bytes, str], Union[bytes, str]]]
        ] = None,
        client_ip: str = "127.0.0.1",
    ) -> FakeChannel:
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
            content_is_form: Whether the content is URL encoded form data. Adds the
                'Content-Type': 'application/x-www-form-urlencoded' header.

            await_result: whether to wait for the request to complete rendering. If
                 true (the default), will pump the test reactor until the the renderer
                 tells the channel the request is finished.

            custom_headers: (name, value) pairs to add as request headers

            client_ip: The IP to use as the requesting IP. Useful for testing
                ratelimiting.

        Returns:
            The FakeChannel object which stores the result of the request.
        """
        return make_request(
            self.reactor,
            self.site,
            method,
            path,
            content,
            access_token,
            request,
            shorthand,
            federation_auth_origin,
            content_is_form,
            await_result,
            custom_headers,
            client_ip,
        )

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

        async def run_bg_updates():
            with LoggingContext("run_bg_updates"):
                while not await stor.db_pool.updates.has_completed_background_updates():
                    await stor.db_pool.updates.do_next_background_update(1)

        hs = setup_test_homeserver(self.addCleanup, *args, **kwargs)
        stor = hs.get_datastore()

        # Run the database background updates, when running against "master".
        if hs.__class__.__name__ == "TestHomeServer":
            self.get_success(run_bg_updates())

        return hs

    def pump(self, by=0.0):
        """
        Pump the reactor enough that Deferreds will fire.
        """
        self.reactor.pump([by] * 100)

    def get_success(self, d, by=0.0):
        if inspect.isawaitable(d):
            d = ensureDeferred(d)
        if not isinstance(d, Deferred):
            return d
        self.pump(by=by)
        return self.successResultOf(d)

    def get_failure(self, d, exc):
        """
        Run a Deferred and get a Failure from it. The failure must be of the type `exc`.
        """
        if inspect.isawaitable(d):
            d = ensureDeferred(d)
        if not isinstance(d, Deferred):
            return d
        self.pump()
        return self.failureResultOf(d, exc)

    def get_success_or_raise(self, d, by=0.0):
        """Drive deferred to completion and return result or raise exception
        on failure.
        """

        if inspect.isawaitable(d):
            deferred = ensureDeferred(d)
        if not isinstance(deferred, Deferred):
            return d

        results = []  # type: list
        deferred.addBoth(results.append)

        self.pump(by=by)

        if not results:
            self.fail(
                "Success result expected on {!r}, found no result instead".format(
                    deferred
                )
            )

        result = results[0]

        if isinstance(result, Failure):
            result.raiseException()

        return result

    def register_user(
        self,
        username: str,
        password: str,
        admin: Optional[bool] = False,
        displayname: Optional[str] = None,
    ) -> str:
        """
        Register a user. Requires the Admin API be registered.

        Args:
            username: The user part of the new user.
            password: The password of the new user.
            admin: Whether the user should be created as an admin or not.
            displayname: The displayname of the new user.

        Returns:
            The MXID of the new user.
        """
        self.hs.config.registration_shared_secret = "shared"

        # Create the user
        channel = self.make_request("GET", "/_synapse/admin/v1/register")
        self.assertEqual(channel.code, 200, msg=channel.result)
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
                "displayname": displayname,
                "password": password,
                "admin": admin,
                "mac": want_mac,
                "inhibit_login": True,
            }
        )
        channel = self.make_request(
            "POST", "/_synapse/admin/v1/register", body.encode("utf8")
        )
        self.assertEqual(channel.code, 200, channel.json_body)

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

        channel = self.make_request(
            "POST", "/_matrix/client/r0/login", json.dumps(body).encode("utf8")
        )
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
        requester = create_requester(user)

        event, context = self.get_success(
            event_creator.create_event(
                requester,
                {
                    "type": EventTypes.Message,
                    "room_id": room_id,
                    "sender": user.to_string(),
                    "content": {"body": secrets.token_hex(), "msgtype": "m.text"},
                },
                prev_event_ids=prev_event_ids,
            )
        )

        if soft_failed:
            event.internal_metadata.soft_failed = True

        self.get_success(
            event_creator.handle_new_client_event(requester, event, context)
        )

        return event.event_id

    def add_extremity(self, room_id, event_id):
        """
        Add the given event as an extremity to the room.
        """
        self.get_success(
            self.hs.get_datastore().db_pool.simple_insert(
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

        channel = self.make_request(
            "POST", "/_matrix/client/r0/login", json.dumps(body).encode("utf8")
        )
        self.assertEqual(channel.code, 403, channel.result)

    def inject_room_member(self, room: str, user: str, membership: Membership) -> None:
        """
        Inject a membership event into a room.

        Deprecated: use event_injection.inject_room_member directly

        Args:
            room: Room ID to inject the event into.
            user: MXID of the user to inject the membership for.
            membership: The membership type.
        """
        self.get_success(
            event_injection.inject_member_event(self.hs, room, user, membership)
        )


class FederatingHomeserverTestCase(HomeserverTestCase):
    """
    A federating homeserver that authenticates incoming requests as `other.example.com`.
    """

    def create_resource_dict(self) -> Dict[str, Resource]:
        d = super().create_resource_dict()
        d["/_matrix/federation"] = TestTransportLayerServer(self.hs)
        return d


class TestTransportLayerServer(JsonResource):
    """A test implementation of TransportLayerServer

    authenticates incoming requests as `other.example.com`.
    """

    def __init__(self, hs):
        super().__init__(hs)

        class Authenticator:
            def authenticate_request(self, request, content):
                return succeed("other.example.com")

        authenticator = Authenticator()

        ratelimiter = FederationRateLimiter(
            hs.get_clock(),
            FederationRateLimitConfig(
                window_size=1,
                sleep_limit=1,
                sleep_msec=1,
                reject_limit=1000,
                concurrent_requests=1000,
            ),
        )

        federation_server.register_servlets(hs, self, authenticator, ratelimiter)


def override_config(extra_config):
    """A decorator which can be applied to test functions to give additional HS config

    For use

    For example:

        class MyTestCase(HomeserverTestCase):
            @override_config({"enable_registration": False, ...})
            def test_foo(self):
                ...

    Args:
        extra_config(dict): Additional config settings to be merged into the default
            config dict before instantiating the test homeserver.
    """

    def decorator(func):
        func._extra_config = extra_config
        return func

    return decorator


TV = TypeVar("TV")


def skip_unless(condition: bool, reason: str) -> Callable[[TV], TV]:
    """A test decorator which will skip the decorated test unless a condition is set

    For example:

    class MyTestCase(TestCase):
        @skip_unless(HAS_FOO, "Cannot test without foo")
        def test_foo(self):
            ...

    Args:
        condition: If true, the test will be skipped
        reason: the reason to give for skipping the test
    """

    def decorator(f: TV) -> TV:
        if not condition:
            f.skip = reason  # type: ignore
        return f

    return decorator
