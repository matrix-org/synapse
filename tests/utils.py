# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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
from synapse.storage import prepare_database
from synapse.server import HomeServer

from synapse.util.logcontext import LoggingContext

from twisted.internet import defer, reactor
from twisted.enterprise.adbapi import ConnectionPool

from collections import namedtuple
from mock import patch, Mock
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

    if datastore is None:
        db_pool = SQLiteMemoryDbPool()
        yield db_pool.prepare()
        hs = HomeServer(
            name, db_pool=db_pool, config=config,
            version_string="Synapse/tests",
            **kargs
        )
    else:
        hs = HomeServer(
            name, db_pool=None, datastore=datastore, config=config,
            version_string="Synapse/tests",
            **kargs
        )

    defer.returnValue(hs)


def get_mock_call_args(pattern_func, mock_func):
    """ Return the arguments the mock function was called with interpreted
    by the pattern functions argument list.
    """
    invoked_args, invoked_kargs = mock_func.call_args
    return getcallargs(pattern_func, *invoked_args, **invoked_kargs)


# This is a mock /resource/ not an entire server
class MockHttpResource(HttpServer):

    def __init__(self, prefix=""):
        self.callbacks = []  # 3-tuple of method/pattern/function
        self.prefix = prefix

    def trigger_get(self, path):
        return self.trigger("GET", path, None)

    @patch('twisted.web.http.Request')
    @defer.inlineCallbacks
    def trigger(self, http_method, path, content, mock_request):
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

        mock_request.requestHeaders.getRawHeaders.return_value=[
            "X-Matrix origin=test,key=,sig="
        ]

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
                    defer.returnValue((e.code, cs_error(e.msg)))

        raise KeyError("No event can handle %s" % path)

    def register_path(self, method, path_pattern, callback):
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

    def time(self):
        return self.now

    def time_msec(self):
        return self.time() * 1000

    def call_later(self, delay, callback):
        current_context = LoggingContext.current_context()

        def wrapped_callback():
            LoggingContext.thread_local.current_context = current_context
            callback()

        t = [self.now + delay, wrapped_callback, False]
        self.timers.append(t)

        return t

    def cancel_call_later(self, timer):
        if timer[2]:
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


class SQLiteMemoryDbPool(ConnectionPool, object):
    def __init__(self):
        super(SQLiteMemoryDbPool, self).__init__(
            "sqlite3", ":memory:",
            cp_min=1,
            cp_max=1,
        )

    def prepare(self):
        return self.runWithConnection(prepare_database)


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

    def get_user_by_token(self, token):
        try:
            return {
                "name": self.tokens_to_users[token],
                "admin": 0,
                "device_id": None,
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
            self.members[r].get(user_id) for r in self.members
            if user_id in self.members[r] and
                self.members[r][user_id].membership in membership_list
        ]

    def get_room_events_stream(self, user_id=None, from_key=None, to_key=None,
                            room_id=None, limit=0, with_feedback=False):
        return ([], from_key)  # TODO

    def get_joined_hosts_for_room(self, room_id):
        return defer.succeed([])

    def persist_event(self, event):
        if event.type == EventTypes.Member:
            room_id = event.room_id
            user = event.state_key
            membership = event.membership
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
        return 0  # TODO (erikj)

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

    def insert_client_ip(self, user, device_id, access_token, ip, user_agent):
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

        failure = AssertionError("Was not expecting call(%s)" %
            _format_call(args, kwargs)
        )

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
            timeout/1000,
            deferred.errback,
            AssertionError(
                "%d pending calls left: %s"% (
                    len([e for e in self.expectations if not e[2].called]),
                    [e for e in self.expectations if not e[2].called]
                )
            )
        )

        yield deferred

        timer.cancel()

        self.calls = []

    def assert_had_no_calls(self):
        if self.calls:
            calls = self.calls
            self.calls = []

            raise AssertionError("Expected not to received any calls, got:\n" +
                "\n".join([
                    "call(%s)" % _format_call(c[0], c[1]) for c in calls
                ])
            )
