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
import logging
import secrets
import time
from typing import (
    Any,
    Awaitable,
    Callable,
    ClassVar,
    Dict,
    Generic,
    Iterable,
    List,
    NoReturn,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
)
from unittest.mock import Mock, patch

import canonicaljson
import signedjson.key
import unpaddedbase64
from typing_extensions import Concatenate, ParamSpec, Protocol

from twisted.internet.defer import Deferred, ensureDeferred
from twisted.python.failure import Failure
from twisted.python.threadpool import ThreadPool
from twisted.test.proto_helpers import MemoryReactor
from twisted.trial import unittest
from twisted.web.resource import Resource
from twisted.web.server import Request

from synapse import events
from synapse.api.constants import EventTypes
from synapse.api.room_versions import KNOWN_ROOM_VERSIONS, RoomVersion
from synapse.config.homeserver import HomeServerConfig
from synapse.config.server import DEFAULT_ROOM_VERSION
from synapse.crypto.event_signing import add_hashes_and_signatures
from synapse.federation.transport.server import TransportLayerServer
from synapse.http.server import JsonResource
from synapse.http.site import SynapseRequest, SynapseSite
from synapse.logging.context import (
    SENTINEL_CONTEXT,
    LoggingContext,
    current_context,
    set_current_context,
)
from synapse.rest import RegisterServletsFunc
from synapse.server import HomeServer
from synapse.storage.keys import FetchKeyResult
from synapse.types import JsonDict, Requester, UserID, create_requester
from synapse.util import Clock
from synapse.util.httpresourcetree import create_resource_tree

from tests.server import (
    CustomHeaderType,
    FakeChannel,
    get_clock,
    make_request,
    setup_test_homeserver,
)
from tests.test_utils import event_injection, setup_awaitable_errors
from tests.test_utils.logging_setup import setup_logging
from tests.utils import default_config, setupdb

setupdb()
setup_logging()

TV = TypeVar("TV")
_ExcType = TypeVar("_ExcType", bound=BaseException, covariant=True)

P = ParamSpec("P")
R = TypeVar("R")
S = TypeVar("S")


class _TypedFailure(Generic[_ExcType], Protocol):
    """Extension to twisted.Failure, where the 'value' has a certain type."""

    @property
    def value(self) -> _ExcType:
        ...


def around(target: TV) -> Callable[[Callable[Concatenate[S, P], R]], None]:
    """A CLOS-style 'around' modifier, which wraps the original method of the
    given instance with another piece of code.

    @around(self)
    def method_name(orig, *args, **kwargs):
        return orig(*args, **kwargs)
    """

    def _around(code: Callable[Concatenate[S, P], R]) -> None:
        name = code.__name__
        orig = getattr(target, name)

        def new(*args: P.args, **kwargs: P.kwargs) -> R:
            return code(orig, *args, **kwargs)

        setattr(target, name, new)

    return _around


class TestCase(unittest.TestCase):
    """A subclass of twisted.trial's TestCase which looks for 'loglevel'
    attributes on both itself and its individual test methods, to override the
    root logger's logging level while that test (case|method) runs."""

    def __init__(self, methodName: str):
        super().__init__(methodName)

        method = getattr(self, methodName)

        level = getattr(method, "loglevel", getattr(self, "loglevel", None))

        @around(self)
        def setUp(orig: Callable[[], R]) -> R:
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
                def tearDown(orig: Callable[[], R]) -> R:
                    ret = orig()
                    logging.getLogger().setLevel(old_level)
                    return ret

                logging.getLogger().setLevel(level)

            # Trial messes with the warnings configuration, thus this has to be
            # done in the context of an individual TestCase.
            self.addCleanup(setup_awaitable_errors())

            return orig()

        @around(self)
        def tearDown(orig: Callable[[], R]) -> R:
            ret = orig()
            # force a GC to workaround problems with deferreds leaking logcontexts when
            # they are GCed (see the logcontext docs)
            gc.collect()
            set_current_context(SENTINEL_CONTEXT)

            return ret

    def assertObjectHasAttributes(self, attrs: Dict[str, object], obj: object) -> None:
        """Asserts that the given object has each of the attributes given, and
        that the value of each matches according to assertEqual."""
        for key in attrs.keys():
            if not hasattr(obj, key):
                raise AssertionError("Expected obj to have a '.%s'" % key)
            try:
                self.assertEqual(attrs[key], getattr(obj, key))
            except AssertionError as e:
                raise (type(e))(f"Assert error for '.{key}':") from e

    def assert_dict(self, required: dict, actual: dict) -> None:
        """Does a partial assert of a dict.

        Args:
            required: The keys and value which MUST be in 'actual'.
            actual: The test result. Extra keys will not be checked.
        """
        for key in required:
            self.assertEqual(
                required[key], actual[key], msg="%s mismatch. %s" % (key, actual)
            )


def DEBUG(target: TV) -> TV:
    """A decorator to set the .loglevel attribute to logging.DEBUG.
    Can apply to either a TestCase or an individual test method."""
    target.loglevel = logging.DEBUG  # type: ignore[attr-defined]
    return target


def INFO(target: TV) -> TV:
    """A decorator to set the .loglevel attribute to logging.INFO.
    Can apply to either a TestCase or an individual test method."""
    target.loglevel = logging.INFO  # type: ignore[attr-defined]
    return target


def logcontext_clean(target: TV) -> TV:
    """A decorator which marks the TestCase or method as 'logcontext_clean'

    ... ie, any logcontext errors should cause a test failure
    """

    def logcontext_error(msg: str) -> NoReturn:
        raise AssertionError("logcontext error: %s" % (msg))

    patcher = patch("synapse.logging.context.logcontext_error", new=logcontext_error)
    return patcher(target)  # type: ignore[call-overload]


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
        servlets: List of servlet registration function.
        user_id (str): The user ID to assume if auth is hijacked.
        hijack_auth: Whether to hijack auth to return the user specified
        in user_id.
    """

    hijack_auth: ClassVar[bool] = True
    needs_threadpool: ClassVar[bool] = False
    servlets: ClassVar[List[RegisterServletsFunc]] = []

    def __init__(self, methodName: str):
        super().__init__(methodName)

        # see if we have any additional config for this test
        method = getattr(self, methodName)
        self._extra_config = getattr(method, "_extra_config", None)

    def setUp(self) -> None:
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
        events.USE_FROZEN_DICTS = self.hs.config.server.use_frozen_dicts

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
            max_request_body_size=4096,
            reactor=self.reactor,
        )

        from tests.rest.client.utils import RestHelper

        self.helper = RestHelper(self.hs, self.site, getattr(self, "user_id", None))

        if hasattr(self, "user_id"):
            if self.hijack_auth:
                assert self.helper.auth_user_id is not None
                token = "some_fake_token"

                # We need a valid token ID to satisfy foreign key constraints.
                token_id = self.get_success(
                    self.hs.get_datastores().main.add_access_token_to_user(
                        self.helper.auth_user_id,
                        token,
                        None,
                        None,
                    )
                )

                # This has to be a function and not just a Mock, because
                # `self.helper.auth_user_id` is temporarily reassigned in some tests
                async def get_requester(*args, **kwargs) -> Requester:
                    assert self.helper.auth_user_id is not None
                    return create_requester(
                        user_id=UserID.from_string(self.helper.auth_user_id),
                        access_token_id=token_id,
                    )

                # Type ignore: mypy doesn't like us assigning to methods.
                self.hs.get_auth().get_user_by_req = get_requester  # type: ignore[assignment]
                self.hs.get_auth().get_user_by_access_token = get_requester  # type: ignore[assignment]
                self.hs.get_auth().get_access_token_from_request = Mock(return_value=token)  # type: ignore[assignment]

        if self.needs_threadpool:
            self.reactor.threadpool = ThreadPool()  # type: ignore[assignment]
            self.addCleanup(self.reactor.threadpool.stop)
            self.reactor.threadpool.start()

        if hasattr(self, "prepare"):
            self.prepare(self.reactor, self.clock, self.hs)

    def tearDown(self) -> None:
        # Reset to not use frozen dicts.
        events.USE_FROZEN_DICTS = False

    def wait_on_thread(self, deferred: Deferred, timeout: int = 10) -> None:
        """
        Wait until a Deferred is done, where it's waiting on a real thread.
        """
        start_time = time.time()

        while not deferred.called:
            if start_time + timeout < time.time():
                raise ValueError("Timed out waiting for threadpool")
            self.reactor.advance(0.01)
            time.sleep(0.01)

    def wait_for_background_updates(self) -> None:
        """Block until all background database updates have completed."""
        store = self.hs.get_datastores().main
        while not self.get_success(
            store.db_pool.updates.has_completed_background_updates()
        ):
            self.get_success(
                store.db_pool.updates.do_next_background_update(False), by=0.1
            )

    def make_homeserver(self, reactor, clock):
        """
        Make and return a homeserver.

        Args:
            reactor: A Twisted Reactor, or something that pretends to be one.
            clock (synapse.util.Clock): The Clock, associated with the reactor.

        Returns:
            A homeserver suitable for testing.

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

    def default_config(self) -> JsonDict:
        """
        Get a default HomeServer config dict.
        """
        config = default_config("test")

        # apply any additional config which was specified via the override_config
        # decorator.
        if self._extra_config is not None:
            config.update(self._extra_config)

        return config

    def prepare(
        self, reactor: MemoryReactor, clock: Clock, homeserver: HomeServer
    ) -> None:
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
        content: Union[bytes, str, JsonDict] = b"",
        access_token: Optional[str] = None,
        request: Type[Request] = SynapseRequest,
        shorthand: bool = True,
        federation_auth_origin: Optional[bytes] = None,
        content_is_form: bool = False,
        await_result: bool = True,
        custom_headers: Optional[Iterable[CustomHeaderType]] = None,
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
            federation_auth_origin: if set to not-None, we will add a fake
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

    def setup_test_homeserver(self, *args: Any, **kwargs: Any) -> HomeServer:
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

        async def run_bg_updates() -> None:
            with LoggingContext("run_bg_updates"):
                self.get_success(stor.db_pool.updates.run_background_updates(False))

        hs = setup_test_homeserver(self.addCleanup, *args, **kwargs)
        stor = hs.get_datastores().main

        # Run the database background updates, when running against "master".
        if hs.__class__.__name__ == "TestHomeServer":
            self.get_success(run_bg_updates())

        return hs

    def pump(self, by: float = 0.0) -> None:
        """
        Pump the reactor enough that Deferreds will fire.
        """
        self.reactor.pump([by] * 100)

    def get_success(self, d: Awaitable[TV], by: float = 0.0) -> TV:
        deferred: Deferred[TV] = ensureDeferred(d)  # type: ignore[arg-type]
        self.pump(by=by)
        return self.successResultOf(deferred)

    def get_failure(
        self, d: Awaitable[Any], exc: Type[_ExcType]
    ) -> _TypedFailure[_ExcType]:
        """
        Run a Deferred and get a Failure from it. The failure must be of the type `exc`.
        """
        deferred: Deferred[Any] = ensureDeferred(d)  # type: ignore[arg-type]
        self.pump()
        return self.failureResultOf(deferred, exc)

    def get_success_or_raise(self, d: Awaitable[TV], by: float = 0.0) -> TV:
        """Drive deferred to completion and return result or raise exception
        on failure.
        """
        deferred: Deferred[TV] = ensureDeferred(d)  # type: ignore[arg-type]

        results: list = []
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
        self.hs.config.registration.registration_shared_secret = "shared"

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
        want_mac_digest = want_mac.hexdigest()

        body = {
            "nonce": nonce,
            "username": username,
            "displayname": displayname,
            "password": password,
            "admin": admin,
            "mac": want_mac_digest,
            "inhibit_login": True,
        }
        channel = self.make_request("POST", "/_synapse/admin/v1/register", body)
        self.assertEqual(channel.code, 200, channel.json_body)

        user_id = channel.json_body["user_id"]
        return user_id

    def register_appservice_user(
        self,
        username: str,
        appservice_token: str,
    ) -> Tuple[str, str]:
        """Register an appservice user as an application service.
        Requires the client-facing registration API be registered.

        Args:
            username: the user to be registered by an application service.
                Should NOT be a full username, i.e. just "localpart" as opposed to "@localpart:hostname"
            appservice_token: the acccess token for that application service.

        Raises: if the request to '/register' does not return 200 OK.

        Returns:
            The MXID of the new user, the device ID of the new user's first device.
        """
        channel = self.make_request(
            "POST",
            "/_matrix/client/r0/register",
            {
                "username": username,
                "type": "m.login.application_service",
            },
            access_token=appservice_token,
        )
        self.assertEqual(channel.code, 200, channel.json_body)
        return channel.json_body["user_id"], channel.json_body["device_id"]

    def login(
        self,
        username: str,
        password: str,
        device_id: Optional[str] = None,
        additional_request_fields: Optional[Dict[str, str]] = None,
        custom_headers: Optional[Iterable[CustomHeaderType]] = None,
    ) -> str:
        """
        Log in a user, and get an access token. Requires the Login API be registered.

        Args:
            username: The localpart to assign to the new user.
            password: The password to assign to the new user.
            device_id: An optional device ID to assign to the new device created during
                login.
            additional_request_fields: A dictionary containing any additional /login
                request fields and their values.
            custom_headers: Custom HTTP headers and values to add to the /login request.

        Returns:
            The newly registered user's Matrix ID.
        """
        body = {"type": "m.login.password", "user": username, "password": password}
        if device_id:
            body["device_id"] = device_id
        if additional_request_fields:
            body.update(additional_request_fields)

        channel = self.make_request(
            "POST",
            "/_matrix/client/r0/login",
            body,
            custom_headers=custom_headers,
        )
        self.assertEqual(channel.code, 200, channel.result)

        access_token = channel.json_body["access_token"]
        return access_token

    def create_and_send_event(
        self,
        room_id: str,
        user: UserID,
        soft_failed: bool = False,
        prev_event_ids: Optional[List[str]] = None,
    ) -> str:
        """
        Create and send an event.

        Args:
            soft_failed: Whether to create a soft failed event or not
            prev_event_ids: Explicitly set the prev events,
                or if None just use the default

        Returns:
            The new event's ID.
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
            event_creator.handle_new_client_event(
                requester, events_and_context=[(event, context)]
            )
        )

        return event.event_id

    def inject_room_member(self, room: str, user: str, membership: str) -> None:
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
    A federating homeserver, set up to validate incoming federation requests
    """

    OTHER_SERVER_NAME = "other.example.com"
    OTHER_SERVER_SIGNATURE_KEY = signedjson.key.generate_signing_key("test")

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        super().prepare(reactor, clock, hs)

        # poke the other server's signing key into the key store, so that we don't
        # make requests for it
        verify_key = signedjson.key.get_verify_key(self.OTHER_SERVER_SIGNATURE_KEY)
        verify_key_id = "%s:%s" % (verify_key.alg, verify_key.version)

        self.get_success(
            hs.get_datastores().main.store_server_verify_keys(
                from_server=self.OTHER_SERVER_NAME,
                ts_added_ms=clock.time_msec(),
                verify_keys=[
                    (
                        self.OTHER_SERVER_NAME,
                        verify_key_id,
                        FetchKeyResult(
                            verify_key=verify_key,
                            valid_until_ts=clock.time_msec() + 10000,
                        ),
                    )
                ],
            )
        )

    def create_resource_dict(self) -> Dict[str, Resource]:
        d = super().create_resource_dict()
        d["/_matrix/federation"] = TransportLayerServer(self.hs)
        return d

    def make_signed_federation_request(
        self,
        method: str,
        path: str,
        content: Optional[JsonDict] = None,
        await_result: bool = True,
        custom_headers: Optional[Iterable[CustomHeaderType]] = None,
        client_ip: str = "127.0.0.1",
    ) -> FakeChannel:
        """Make an inbound signed federation request to this server

        The request is signed as if it came from "other.example.com", which our HS
        already has the keys for.
        """

        if custom_headers is None:
            custom_headers = []
        else:
            custom_headers = list(custom_headers)

        custom_headers.append(
            (
                "Authorization",
                _auth_header_for_request(
                    origin=self.OTHER_SERVER_NAME,
                    destination=self.hs.hostname,
                    signing_key=self.OTHER_SERVER_SIGNATURE_KEY,
                    method=method,
                    path=path,
                    content=content,
                ),
            )
        )

        return make_request(
            self.reactor,
            self.site,
            method=method,
            path=path,
            content=content if content is not None else "",
            shorthand=False,
            await_result=await_result,
            custom_headers=custom_headers,
            client_ip=client_ip,
        )

    def add_hashes_and_signatures_from_other_server(
        self,
        event_dict: JsonDict,
        room_version: RoomVersion = KNOWN_ROOM_VERSIONS[DEFAULT_ROOM_VERSION],
    ) -> JsonDict:
        """Adds hashes and signatures to the given event dict

        Returns:
             The modified event dict, for convenience
        """
        add_hashes_and_signatures(
            room_version,
            event_dict,
            signature_name=self.OTHER_SERVER_NAME,
            signing_key=self.OTHER_SERVER_SIGNATURE_KEY,
        )
        return event_dict


def _auth_header_for_request(
    origin: str,
    destination: str,
    signing_key: signedjson.key.SigningKey,
    method: str,
    path: str,
    content: Optional[JsonDict],
) -> str:
    """Build a suitable Authorization header for an outgoing federation request"""
    request_description: JsonDict = {
        "method": method,
        "uri": path,
        "destination": destination,
        "origin": origin,
    }
    if content is not None:
        request_description["content"] = content
    signature_base64 = unpaddedbase64.encode_base64(
        signing_key.sign(
            canonicaljson.encode_canonical_json(request_description)
        ).signature
    )
    return (
        f"X-Matrix origin={origin},"
        f"key={signing_key.alg}:{signing_key.version},"
        f"sig={signature_base64}"
    )


def override_config(extra_config: JsonDict) -> Callable[[TV], TV]:
    """A decorator which can be applied to test functions to give additional HS config

    For use

    For example:

        class MyTestCase(HomeserverTestCase):
            @override_config({"enable_registration": False, ...})
            def test_foo(self):
                ...

    Args:
        extra_config: Additional config settings to be merged into the default
            config dict before instantiating the test homeserver.
    """

    def decorator(func: TV) -> TV:
        # This attribute is being defined.
        func._extra_config = extra_config  # type: ignore[attr-defined]
        return func

    return decorator


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
