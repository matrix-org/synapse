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

import atexit
import hashlib
import os
import time
import uuid
import warnings
from inspect import getcallargs

from mock import Mock, patch
from six.moves.urllib import parse as urlparse

from twisted.internet import defer, reactor

from synapse.api.constants import EventTypes
from synapse.api.errors import CodeMessageException, cs_error
from synapse.config.server import ServerConfig
from synapse.federation.transport import server
from synapse.http.server import HttpServer
from synapse.server import HomeServer
from synapse.storage import DataStore
from synapse.storage.engines import PostgresEngine, create_engine
from synapse.storage.prepare_database import (
    _get_or_create_schema_state,
    _setup_new_database,
    prepare_database,
)
from synapse.util.logcontext import LoggingContext
from synapse.util.ratelimitutils import FederationRateLimiter

# set this to True to run the tests against postgres instead of sqlite.
USE_POSTGRES_FOR_TESTS = os.environ.get("SYNAPSE_POSTGRES", False)
LEAVE_DB = os.environ.get("SYNAPSE_LEAVE_DB", False)
POSTGRES_USER = os.environ.get("SYNAPSE_POSTGRES_USER", "postgres")
POSTGRES_BASE_DB = "_synapse_unit_tests_base_%s" % (os.getpid(),)


def setupdb():

    # If we're using PostgreSQL, set up the db once
    if USE_POSTGRES_FOR_TESTS:
        pgconfig = {
            "name": "psycopg2",
            "args": {
                "database": POSTGRES_BASE_DB,
                "user": POSTGRES_USER,
                "cp_min": 1,
                "cp_max": 5,
            },
        }
        config = Mock()
        config.password_providers = []
        config.database_config = pgconfig
        db_engine = create_engine(pgconfig)
        db_conn = db_engine.module.connect(user=POSTGRES_USER)
        db_conn.autocommit = True
        cur = db_conn.cursor()
        cur.execute("DROP DATABASE IF EXISTS %s;" % (POSTGRES_BASE_DB,))
        cur.execute("CREATE DATABASE %s;" % (POSTGRES_BASE_DB,))
        cur.close()
        db_conn.close()

        # Set up in the db
        db_conn = db_engine.module.connect(
            database=POSTGRES_BASE_DB, user=POSTGRES_USER
        )
        cur = db_conn.cursor()
        _get_or_create_schema_state(cur, db_engine)
        _setup_new_database(cur, db_engine)
        db_conn.commit()
        cur.close()
        db_conn.close()

        def _cleanup():
            db_conn = db_engine.module.connect(user=POSTGRES_USER)
            db_conn.autocommit = True
            cur = db_conn.cursor()
            cur.execute("DROP DATABASE IF EXISTS %s;" % (POSTGRES_BASE_DB,))
            cur.close()
            db_conn.close()

        atexit.register(_cleanup)


class TestHomeServer(HomeServer):
    DATASTORE_CLASS = DataStore


@defer.inlineCallbacks
def setup_test_homeserver(
    cleanup_func,
    name="test",
    datastore=None,
    config=None,
    reactor=None,
    homeserverToUse=TestHomeServer,
    **kargs
):
    """
    Setup a homeserver suitable for running tests against.  Keyword arguments
    are passed to the Homeserver constructor.

    If no datastore is supplied, one is created and given to the homeserver.

    Args:
        cleanup_func : The function used to register a cleanup routine for
                       after the test.
    """
    if reactor is None:
        from twisted.internet import reactor

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
        config.email_enable_notifs = False
        config.block_non_admin_invites = False
        config.federation_domain_whitelist = None
        config.federation_rc_reject_limit = 10
        config.federation_rc_sleep_limit = 10
        config.federation_rc_sleep_delay = 100
        config.federation_rc_concurrent = 10
        config.filter_timeline_limit = 5000
        config.user_directory_search_all_users = False
        config.user_consent_server_notice_content = None
        config.block_events_without_consent_error = None
        config.media_storage_providers = []
        config.auto_join_rooms = []
        config.limit_usage_by_mau = False
        config.hs_disabled = False
        config.hs_disabled_message = ""
        config.hs_disabled_limit_type = ""
        config.max_mau_value = 50
        config.mau_trial_days = 0
        config.mau_limits_reserved_threepids = []
        config.admin_contact = None
        config.rc_messages_per_second = 10000
        config.rc_message_burst_count = 10000

        # we need a sane default_room_version, otherwise attempts to create rooms will
        # fail.
        config.default_room_version = "1"

        # disable user directory updates, because they get done in the
        # background, which upsets the test runner.
        config.update_user_directory = False

        def is_threepid_reserved(threepid):
            return ServerConfig.is_threepid_reserved(config, threepid)

        config.is_threepid_reserved.side_effect = is_threepid_reserved

    config.use_frozen_dicts = True
    config.ldap_enabled = False

    if "clock" not in kargs:
        kargs["clock"] = MockClock()

    if USE_POSTGRES_FOR_TESTS:
        test_db = "synapse_test_%s" % uuid.uuid4().hex

        config.database_config = {
            "name": "psycopg2",
            "args": {"database": test_db, "cp_min": 1, "cp_max": 5},
        }
    else:
        config.database_config = {
            "name": "sqlite3",
            "args": {"database": ":memory:", "cp_min": 1, "cp_max": 1},
        }

    db_engine = create_engine(config.database_config)

    # Create the database before we actually try and connect to it, based off
    # the template database we generate in setupdb()
    if datastore is None and isinstance(db_engine, PostgresEngine):
        db_conn = db_engine.module.connect(
            database=POSTGRES_BASE_DB, user=POSTGRES_USER
        )
        db_conn.autocommit = True
        cur = db_conn.cursor()
        cur.execute("DROP DATABASE IF EXISTS %s;" % (test_db,))
        cur.execute(
            "CREATE DATABASE %s WITH TEMPLATE %s;" % (test_db, POSTGRES_BASE_DB)
        )
        cur.close()
        db_conn.close()

    # we need to configure the connection pool to run the on_new_connection
    # function, so that we can test code that uses custom sqlite functions
    # (like rank).
    config.database_config["args"]["cp_openfun"] = db_engine.on_new_connection

    if datastore is None:
        hs = homeserverToUse(
            name,
            config=config,
            db_config=config.database_config,
            version_string="Synapse/tests",
            database_engine=db_engine,
            room_list_handler=object(),
            tls_server_context_factory=Mock(),
            tls_client_options_factory=Mock(),
            reactor=reactor,
            **kargs
        )

        # Prepare the DB on SQLite -- PostgreSQL is a copy of an already up to
        # date db
        if not isinstance(db_engine, PostgresEngine):
            db_conn = hs.get_db_conn()
            yield prepare_database(db_conn, db_engine, config)
            db_conn.commit()
            db_conn.close()

        else:
            # We need to do cleanup on PostgreSQL
            def cleanup():
                import psycopg2

                # Close all the db pools
                hs.get_db_pool().close()

                dropped = False

                # Drop the test database
                db_conn = db_engine.module.connect(
                    database=POSTGRES_BASE_DB, user=POSTGRES_USER
                )
                db_conn.autocommit = True
                cur = db_conn.cursor()

                # Try a few times to drop the DB. Some things may hold on to the
                # database for a few more seconds due to flakiness, preventing
                # us from dropping it when the test is over. If we can't drop
                # it, warn and move on.
                for x in range(5):
                    try:
                        cur.execute("DROP DATABASE IF EXISTS %s;" % (test_db,))
                        db_conn.commit()
                        dropped = True
                    except psycopg2.OperationalError as e:
                        warnings.warn(
                            "Couldn't drop old db: " + str(e), category=UserWarning
                        )
                        time.sleep(0.5)

                cur.close()
                db_conn.close()

                if not dropped:
                    warnings.warn("Failed to drop old DB.", category=UserWarning)

            if not LEAVE_DB:
                # Register the cleanup hook
                cleanup_func(cleanup)

        hs.setup()
    else:
        hs = homeserverToUse(
            name,
            db_pool=None,
            datastore=datastore,
            config=config,
            version_string="Synapse/tests",
            database_engine=db_engine,
            room_list_handler=object(),
            tls_server_context_factory=Mock(),
            tls_client_options_factory=Mock(),
            reactor=reactor,
            **kargs
        )

    # bcrypt is far too slow to be doing in unit tests
    # Need to let the HS build an auth handler and then mess with it
    # because AuthHandler's constructor requires the HS, so we can't make one
    # beforehand and pass it in to the HS's constructor (chicken / egg)
    hs.get_auth_handler().hash = lambda p: hashlib.md5(p.encode('utf8')).hexdigest()
    hs.get_auth_handler().validate_hash = (
        lambda p, h: hashlib.md5(p.encode('utf8')).hexdigest() == h
    )

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
                concurrent_requests=hs.config.federation_rc_concurrent,
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
        return self.trigger(b"GET", path, None)

    @patch('twisted.web.http.Request')
    @defer.inlineCallbacks
    def trigger(
        self, http_method, path, content, mock_request, federation_auth_origin=None
    ):
        """ Fire an HTTP event.

        Args:
            http_method : The HTTP method
            path : The HTTP path
            content : The HTTP body
            mock_request : Mocked request to pass to the event so it can get
                           content.
            federation_auth_origin (bytes|None): domain to authenticate as, for federation
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

        mock_request.method = http_method.encode('ascii')
        mock_request.uri = path.encode('ascii')

        mock_request.getClientIP.return_value = "-"

        headers = {}
        if federation_auth_origin is not None:
            headers[b"Authorization"] = [
                b"X-Matrix origin=%s,key=,sig=" % (federation_auth_origin,)
            ]
        mock_request.requestHeaders.getRawHeaders = mock_getRawHeaders(headers)

        # return the right path if the event requires it
        mock_request.path = path

        # add in query params to the right place
        try:
            mock_request.args = urlparse.parse_qs(path.split('?')[1])
            mock_request.path = path.split('?')[0]
            path = mock_request.path
        except Exception:
            pass

        if isinstance(path, bytes):
            path = path.decode('utf8')

        for (method, pattern, func) in self.callbacks:
            if http_method != method:
                continue

            matcher = pattern.match(path)
            if matcher:
                try:
                    args = [urlparse.unquote(u) for u in matcher.groups()]

                    (code, response) = yield func(mock_request, *args)
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


def _format_call(args, kwargs):
    return ", ".join(
        ["%r" % (a) for a in args] + ["%s=%r" % (k, v) for k, v in kwargs.items()]
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
            raise ValueError(
                "%r has no pending calls to handle call(%s)"
                % (self, _format_call(args, kwargs))
            )

        for (call, result, d) in self.expectations:
            if args == call[1] and kwargs == call[2]:
                d.callback(None)
                return result

        failure = AssertionError(
            "Was not expecting call(%s)" % (_format_call(args, kwargs))
        )

        for _, _, d in self.expectations:
            try:
                d.errback(failure)
            except Exception:
                pass

        raise failure

    def expect_call_and_return(self, call, result):
        self.expectations.append((call, result, defer.Deferred()))

    @defer.inlineCallbacks
    def await_calls(self, timeout=1000):
        deferred = defer.DeferredList(
            [d for _, _, d in self.expectations], fireOnOneErrback=True
        )

        timer = reactor.callLater(
            timeout / 1000,
            deferred.errback,
            AssertionError(
                "%d pending calls left: %s"
                % (
                    len([e for e in self.expectations if not e[2].called]),
                    [e for e in self.expectations if not e[2].called],
                )
            ),
        )

        yield deferred

        timer.cancel()

        self.calls = []

    def assert_had_no_calls(self):
        if self.calls:
            calls = self.calls
            self.calls = []

            raise AssertionError(
                "Expected not to received any calls, got:\n"
                + "\n".join(["call(%s)" % _format_call(c[0], c[1]) for c in calls])
            )


@defer.inlineCallbacks
def create_room(hs, room_id, creator_id):
    """Creates and persist a creation event for the given room

    Args:
        hs
        room_id (str)
        creator_id (str)
    """

    store = hs.get_datastore()
    event_builder_factory = hs.get_event_builder_factory()
    event_creation_handler = hs.get_event_creation_handler()

    builder = event_builder_factory.new(
        {
            "type": EventTypes.Create,
            "state_key": "",
            "sender": creator_id,
            "room_id": room_id,
            "content": {},
        }
    )

    event, context = yield event_creation_handler.create_new_client_event(builder)

    yield store.persist_event(event, context)
