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

from synapse.http.server import HttpServer
from synapse.api.errors import cs_error, CodeMessageException, StoreError
from synapse.api.constants import EventTypes
from synapse.storage.prepare_database import prepare_database
from synapse.storage.engines import create_engine
from synapse.server import HomeServer
from synapse.federation.transport import server
from synapse.util.ratelimitutils import FederationRateLimiter

from synapse.util.logcontext import LoggingContext

from twisted.internet import defer, reactor
from twisted.enterprise.adbapi import ConnectionPool

from collections import namedtuple
from mock import patch, Mock
import hashlib
import urllib
import urlparse

from inspect import getcallargs


@defer.inlineCallbacks
def setup_test_homeserver(name="test", datastore=None, config=None, **kargs):
    """Setup a homeserver suitable for running tests against. Keyword arguments
    are passed to the Homeserver constructor. If no datastore is supplied a
    datastore backed by an in-memory sqlite db will be given to the HS.
    """
    if config is None:
        config = Mock()
        config.signing_key = [MockKey()]
        config.event_cache_size = 1
        config.enable_registration = True
        config.macaroon_secret_key = "not even a little secret"
        config.expire_access_token = False
        config.server_name = name
        config.trusted_third_party_id_servers = []
        config.room_invite_state_types = []
        config.password_providers = []
        config.worker_replication_url = ""
        config.worker_app = None

    config.use_frozen_dicts = True
    config.database_config = {"name": "sqlite3"}
    config.ldap_enabled = False

    if "clock" not in kargs:
        kargs["clock"] = MockClock()

    if datastore is None:
        db_pool = SQLiteMemoryDbPool()
        yield db_pool.prepare()
        hs = HomeServer(
            name, db_pool=db_pool, config=config,
            version_string="Synapse/tests",
            database_engine=create_engine(config.database_config),
            get_db_conn=db_pool.get_db_conn,
            room_list_handler=object(),
            tls_server_context_factory=Mock(),
            **kargs
        )
        hs.setup()
    else:
        hs = HomeServer(
            name, db_pool=None, datastore=datastore, config=config,
            version_string="Synapse/tests",
            database_engine=create_engine(config.database_config),
            room_list_handler=object(),
            tls_server_context_factory=Mock(),
            **kargs
        )

    # bcrypt is far too slow to be doing in unit tests
    # Need to let the HS build an auth handler and then mess with it
    # because AuthHandler's constructor requires the HS, so we can't make one
    # beforehand and pass it in to the HS's constructor (chicken / egg)
    hs.get_auth_handler().hash = lambda p: hashlib.md5(p).hexdigest()
    hs.get_auth_handler().validate_hash = lambda p, h: hashlib.md5(p).hexdigest() == h

    fed = kargs.get("resource_for_federation", None)
    if fed:
        server.register_servlets(
            hs,
            resource=fed,
            authenticator=server.Authenticator(hs),
            ratelimiter=FederationRateLimiter(
                hs.get_clock(),
                window_size=hs.config.federation_rc_window_size,
                sleep_limit=hs.config.federation_rc_sleep_limit,
                sleep_msec=hs.config.federation_rc_sleep_delay,
                reject_limit=hs.config.federation_rc_reject_limit,
                concurrent_requests=hs.config.federation_rc_concurrent
            ),
        )

    defer.returnValue(hs)


def get_mock_call_args(pattern_func, mock_func):
    """ Return the arguments the mock function was called with interpreted
    by the pattern functions argument list.
    """
    invoked_args, invoked_kargs = mock_func.call_args
    return getcallargs(pattern_func, *invoked_args, **invoked_kargs)


def mock_getRawHeaders(headers=None):
    headers = headers if headers is not None else {}

    def getRawHeaders(name, default=None):
        return headers.get(name, default)

    return getRawHeaders


# This is a mock /resource/ not an entire server
class MockHttpResource(HttpServer):

    def __init__(self, prefix=""):
        self.callbacks = []  # 3-tuple of method/pattern/function
        self.prefix = prefix

    def trigger_get(self, path):
        return self.trigger("GET", path, None)

    @patch('twisted.web.http.Request')
    @defer.inlineCallbacks
    def trigger(self, http_method, path, content, mock_request, federation_auth=False):
        """ Fire an HTTP event.

        Args:
            http_method : The HTTP method
            path : The HTTP path
            content : The HTTP body
            mock_request : Mocked request to pass to the event so it can get
                           content.
        Returns:
            A tuple of (code, response)
        Raises:
            KeyError If no event is found which will handle the path.
        """
        path = self.prefix + path

        # annoyingly we return a twisted http request which has chained calls
        # to get at the http content, hence mock it here.
        mock_content = Mock()
        config = {'read.return_value': content}
        mock_content.configure_mock(**config)
        mock_request.content = mock_content

        mock_request.method = http_method
        mock_request.uri = path

        mock_request.getClientIP.return_value = "-"

        headers = {}
        if federation_auth:
            headers["Authorization"] = ["X-Matrix origin=test,key=,sig="]
        mock_request.requestHeaders.getRawHeaders = mock_getRawHeaders(headers)

        # return the right path if the event requires it
        mock_request.path = path

        # add in query params to the right place
        try:
            mock_request.args = urlparse.parse_qs(path.split('?')[1])
            mock_request.path = path.split('?')[0]
            path = mock_request.path
        except:
            pass

        for (method, pattern, func) in self.callbacks:
            if http_method != method:
                continue

            matcher = pattern.match(path)
            if matcher:
                try:
                    args = [
                        urllib.unquote(u).decode("UTF-8")
                        for u in matcher.groups()
                    ]

                    (code, response) = yield func(
                        mock_request,
                        *args
                    )
                    defer.returnValue((code, response))
                except CodeMessageException as e:
                    defer.returnValue((e.code, cs_error(e.msg, code=e.errcode)))

        raise KeyError("No event can handle %s" % path)

    def register_paths(self, method, path_patterns, callback):
        for path_pattern in path_patterns:
            self.callbacks.append((method, path_pattern, callback))


class MockKey(object):
    alg = "mock_alg"
    version = "mock_version"
    signature = b"\x9a\x87$"

    @property
    def verify_key(self):
        return self

    def sign(self, message):
        return self

    def verify(self, message, sig):
        assert sig == b"\x9a\x87$"


class MockClock(object):
    now = 1000

    def __init__(self):
        # list of lists of [absolute_time, callback, expired] in no particular
        # order
        self.timers = []
        self.loopers = []

    def time(self):
        return self.now

    def time_msec(self):
        return self.time() * 1000

    def call_later(self, delay, callback, *args, **kwargs):
        current_context = LoggingContext.current_context()

        def wrapped_callback():
            LoggingContext.thread_local.current_context = current_context
            callback(*args, **kwargs)

        t = [self.now + delay, wrapped_callback, False]
        self.timers.append(t)

        return t

    def looping_call(self, function, interval):
        self.loopers.append([function, interval / 1000., self.now])

    def cancel_call_later(self, timer, ignore_errs=False):
        if timer[2]:
            if not ignore_errs:
                raise Exception("Cannot cancel an expired timer")

        timer[2] = True
        self.timers = [t for t in self.timers if t != timer]

    # For unit testing
    def advance_time(self, secs):
        self.now += secs

        timers = self.timers
        self.timers = []

        for t in timers:
            time, callback, expired = t

            if expired:
                raise Exception("Timer already expired")

            if self.now >= time:
                t[2] = True
                callback()
            else:
                self.timers.append(t)

        for looped in self.loopers:
            func, interval, last = looped
            if last + interval < self.now:
                func()
                looped[2] = self.now

    def advance_time_msec(self, ms):
        self.advance_time(ms / 1000.)

    def time_bound_deferred(self, d, *args, **kwargs):
        # We don't bother timing things out for now.
        return d


class SQLiteMemoryDbPool(ConnectionPool, object):
    def __init__(self):
        super(SQLiteMemoryDbPool, self).__init__(
            "sqlite3", ":memory:",
            cp_min=1,
            cp_max=1,
        )

        self.config = Mock()
        self.config.database_config = {"name": "sqlite3"}

    def prepare(self):
        engine = self.create_engine()
        return self.runWithConnection(
            lambda conn: prepare_database(conn, engine, self.config)
        )

    def get_db_conn(self):
        conn = self.connect()
        engine = self.create_engine()
        prepare_database(conn, engine, self.config)
        return conn

    def create_engine(self):
        return create_engine(self.config.database_config)


class MemoryDataStore(object):

    Room = namedtuple(
        "Room",
        ["room_id", "is_public", "creator"]
    )

    def __init__(self):
        self.tokens_to_users = {}
        self.paths_to_content = {}

        self.members = {}
        self.rooms = {}

        self.current_state = {}
        self.events = []

    class Snapshot(namedtuple("Snapshot", "room_id user_id membership_state")):
        def fill_out_prev_events(self, event):
            pass

    def snapshot_room(self, room_id, user_id, state_type=None, state_key=None):
        return self.Snapshot(
            room_id, user_id, self.get_room_member(user_id, room_id)
        )

    def register(self, user_id, token, password_hash):
        if user_id in self.tokens_to_users.values():
            raise StoreError(400, "User in use.")
        self.tokens_to_users[token] = user_id

    def get_user_by_access_token(self, token):
        try:
            return {
                "name": self.tokens_to_users[token],
            }
        except:
            raise StoreError(400, "User does not exist.")

    def get_room(self, room_id):
        try:
            return self.rooms[room_id]
        except:
            return None

    def store_room(self, room_id, room_creator_user_id, is_public):
        if room_id in self.rooms:
            raise StoreError(409, "Conflicting room!")

        room = MemoryDataStore.Room(
            room_id=room_id,
            is_public=is_public,
            creator=room_creator_user_id
        )
        self.rooms[room_id] = room

    def get_room_member(self, user_id, room_id):
        return self.members.get(room_id, {}).get(user_id)

    def get_room_members(self, room_id, membership=None):
        if membership:
            return [
                v for k, v in self.members.get(room_id, {}).items()
                if v.membership == membership
            ]
        else:
            return self.members.get(room_id, {}).values()

    def get_rooms_for_user_where_membership_is(self, user_id, membership_list):
        return [
            m[user_id] for m in self.members.values()
            if user_id in m and m[user_id].membership in membership_list
        ]

    def get_room_events_stream(self, user_id=None, from_key=None, to_key=None,
                               limit=0, with_feedback=False):
        return ([], from_key)  # TODO

    def get_joined_hosts_for_room(self, room_id):
        return defer.succeed([])

    def persist_event(self, event):
        if event.type == EventTypes.Member:
            room_id = event.room_id
            user = event.state_key
            self.members.setdefault(room_id, {})[user] = event

        if hasattr(event, "state_key"):
            key = (event.room_id, event.type, event.state_key)
            self.current_state[key] = event

        self.events.append(event)

    def get_current_state(self, room_id, event_type=None, state_key=""):
        if event_type:
            key = (room_id, event_type, state_key)
            if self.current_state.get(key):
                return [self.current_state.get(key)]
            return None
        else:
            return [
                e for e in self.current_state
                if e[0] == room_id
            ]

    def set_presence_state(self, user_localpart, state):
        return defer.succeed({"state": 0})

    def get_presence_list(self, user_localpart, accepted):
        return []

    def get_room_events_max_id(self):
        return "s0"  # TODO (erikj)

    def get_send_event_level(self, room_id):
        return defer.succeed(0)

    def get_power_level(self, room_id, user_id):
        return defer.succeed(0)

    def get_add_state_level(self, room_id):
        return defer.succeed(0)

    def get_room_join_rule(self, room_id):
        # TODO (erikj): This should be configurable
        return defer.succeed("invite")

    def get_ops_levels(self, room_id):
        return defer.succeed((5, 5, 5))

    def insert_client_ip(self, user, access_token, ip, user_agent):
        return defer.succeed(None)


def _format_call(args, kwargs):
    return ", ".join(
        ["%r" % (a) for a in args] +
        ["%s=%r" % (k, v) for k, v in kwargs.items()]
    )


class DeferredMockCallable(object):
    """A callable instance that stores a set of pending call expectations and
    return values for them. It allows a unit test to assert that the given set
    of function calls are eventually made, by awaiting on them to be called.
    """

    def __init__(self):
        self.expectations = []
        self.calls = []

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))

        if not self.expectations:
            raise ValueError("%r has no pending calls to handle call(%s)" % (
                self, _format_call(args, kwargs))
            )

        for (call, result, d) in self.expectations:
            if args == call[1] and kwargs == call[2]:
                d.callback(None)
                return result

        failure = AssertionError("Was not expecting call(%s)" % (
            _format_call(args, kwargs)
        ))

        for _, _, d in self.expectations:
            try:
                d.errback(failure)
            except:
                pass

        raise failure

    def expect_call_and_return(self, call, result):
        self.expectations.append((call, result, defer.Deferred()))

    @defer.inlineCallbacks
    def await_calls(self, timeout=1000):
        deferred = defer.DeferredList(
            [d for _, _, d in self.expectations],
            fireOnOneErrback=True
        )

        timer = reactor.callLater(
            timeout / 1000,
            deferred.errback,
            AssertionError("%d pending calls left: %s" % (
                len([e for e in self.expectations if not e[2].called]),
                [e for e in self.expectations if not e[2].called]
            ))
        )

        yield deferred

        timer.cancel()

        self.calls = []

    def assert_had_no_calls(self):
        if self.calls:
            calls = self.calls
            self.calls = []

            raise AssertionError(
                "Expected not to received any calls, got:\n" + "\n".join([
                    "call(%s)" % _format_call(c[0], c[1]) for c in calls
                ])
            )
