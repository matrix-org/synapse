# -*- coding: utf-8 -*-
# Copyright 2015 - 2016 OpenMarket Ltd
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

from mock import Mock

import pymacaroons

from twisted.internet import defer

import synapse.handlers.auth
from synapse.api.auth import Auth
from synapse.api.errors import AuthError, Codes, ResourceLimitError
from synapse.types import UserID

from tests import unittest
from tests.utils import mock_getRawHeaders, setup_test_homeserver


class TestHandlers(object):
    def __init__(self, hs):
        self.auth_handler = synapse.handlers.auth.AuthHandler(hs)


class AuthTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        self.state_handler = Mock()
        self.store = Mock()

        self.hs = yield setup_test_homeserver(self.addCleanup, handlers=None)
        self.hs.get_datastore = Mock(return_value=self.store)
        self.hs.handlers = TestHandlers(self.hs)
        self.auth = Auth(self.hs)

        self.test_user = "@foo:bar"
        self.test_token = b"_test_token_"

        # this is overridden for the appservice tests
        self.store.get_app_service_by_token = Mock(return_value=None)

    @defer.inlineCallbacks
    def test_get_user_by_req_user_valid_token(self):
        user_info = {"name": self.test_user, "token_id": "ditto", "device_id": "device"}
        self.store.get_user_by_access_token = Mock(return_value=user_info)

        request = Mock(args={})
        request.args[b"access_token"] = [self.test_token]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        requester = yield self.auth.get_user_by_req(request)
        self.assertEquals(requester.user.to_string(), self.test_user)

    def test_get_user_by_req_user_bad_token(self):
        self.store.get_user_by_access_token = Mock(return_value=None)

        request = Mock(args={})
        request.args[b"access_token"] = [self.test_token]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        d = self.auth.get_user_by_req(request)
        self.failureResultOf(d, AuthError)

    def test_get_user_by_req_user_missing_token(self):
        user_info = {"name": self.test_user, "token_id": "ditto"}
        self.store.get_user_by_access_token = Mock(return_value=user_info)

        request = Mock(args={})
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        d = self.auth.get_user_by_req(request)
        self.failureResultOf(d, AuthError)

    @defer.inlineCallbacks
    def test_get_user_by_req_appservice_valid_token(self):
        app_service = Mock(
            token="foobar", url="a_url", sender=self.test_user, ip_range_whitelist=None
        )
        self.store.get_app_service_by_token = Mock(return_value=app_service)
        self.store.get_user_by_access_token = Mock(return_value=None)

        request = Mock(args={})
        request.getClientIP.return_value = "127.0.0.1"
        request.args[b"access_token"] = [self.test_token]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        requester = yield self.auth.get_user_by_req(request)
        self.assertEquals(requester.user.to_string(), self.test_user)

    @defer.inlineCallbacks
    def test_get_user_by_req_appservice_valid_token_good_ip(self):
        from netaddr import IPSet

        app_service = Mock(
            token="foobar",
            url="a_url",
            sender=self.test_user,
            ip_range_whitelist=IPSet(["192.168/16"]),
        )
        self.store.get_app_service_by_token = Mock(return_value=app_service)
        self.store.get_user_by_access_token = Mock(return_value=None)

        request = Mock(args={})
        request.getClientIP.return_value = "192.168.10.10"
        request.args[b"access_token"] = [self.test_token]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        requester = yield self.auth.get_user_by_req(request)
        self.assertEquals(requester.user.to_string(), self.test_user)

    def test_get_user_by_req_appservice_valid_token_bad_ip(self):
        from netaddr import IPSet

        app_service = Mock(
            token="foobar",
            url="a_url",
            sender=self.test_user,
            ip_range_whitelist=IPSet(["192.168/16"]),
        )
        self.store.get_app_service_by_token = Mock(return_value=app_service)
        self.store.get_user_by_access_token = Mock(return_value=None)

        request = Mock(args={})
        request.getClientIP.return_value = "131.111.8.42"
        request.args[b"access_token"] = [self.test_token]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        d = self.auth.get_user_by_req(request)
        self.failureResultOf(d, AuthError)

    def test_get_user_by_req_appservice_bad_token(self):
        self.store.get_app_service_by_token = Mock(return_value=None)
        self.store.get_user_by_access_token = Mock(return_value=None)

        request = Mock(args={})
        request.args[b"access_token"] = [self.test_token]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        d = self.auth.get_user_by_req(request)
        self.failureResultOf(d, AuthError)

    def test_get_user_by_req_appservice_missing_token(self):
        app_service = Mock(token="foobar", url="a_url", sender=self.test_user)
        self.store.get_app_service_by_token = Mock(return_value=app_service)
        self.store.get_user_by_access_token = Mock(return_value=None)

        request = Mock(args={})
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        d = self.auth.get_user_by_req(request)
        self.failureResultOf(d, AuthError)

    @defer.inlineCallbacks
    def test_get_user_by_req_appservice_valid_token_valid_user_id(self):
        masquerading_user_id = b"@doppelganger:matrix.org"
        app_service = Mock(
            token="foobar", url="a_url", sender=self.test_user, ip_range_whitelist=None
        )
        app_service.is_interested_in_user = Mock(return_value=True)
        self.store.get_app_service_by_token = Mock(return_value=app_service)
        self.store.get_user_by_access_token = Mock(return_value=None)

        request = Mock(args={})
        request.getClientIP.return_value = "127.0.0.1"
        request.args[b"access_token"] = [self.test_token]
        request.args[b"user_id"] = [masquerading_user_id]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        requester = yield self.auth.get_user_by_req(request)
        self.assertEquals(
            requester.user.to_string(), masquerading_user_id.decode('utf8')
        )

    def test_get_user_by_req_appservice_valid_token_bad_user_id(self):
        masquerading_user_id = b"@doppelganger:matrix.org"
        app_service = Mock(
            token="foobar", url="a_url", sender=self.test_user, ip_range_whitelist=None
        )
        app_service.is_interested_in_user = Mock(return_value=False)
        self.store.get_app_service_by_token = Mock(return_value=app_service)
        self.store.get_user_by_access_token = Mock(return_value=None)

        request = Mock(args={})
        request.getClientIP.return_value = "127.0.0.1"
        request.args[b"access_token"] = [self.test_token]
        request.args[b"user_id"] = [masquerading_user_id]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        d = self.auth.get_user_by_req(request)
        self.failureResultOf(d, AuthError)

    @defer.inlineCallbacks
    def test_get_user_from_macaroon(self):
        # TODO(danielwh): Remove this mock when we remove the
        # get_user_by_access_token fallback.
        self.store.get_user_by_access_token = Mock(
            return_value={"name": "@baldrick:matrix.org", "device_id": "device"}
        )

        user_id = "@baldrick:matrix.org"
        macaroon = pymacaroons.Macaroon(
            location=self.hs.config.server_name,
            identifier="key",
            key=self.hs.config.macaroon_secret_key,
        )
        macaroon.add_first_party_caveat("gen = 1")
        macaroon.add_first_party_caveat("type = access")
        macaroon.add_first_party_caveat("user_id = %s" % (user_id,))
        user_info = yield self.auth.get_user_by_access_token(macaroon.serialize())
        user = user_info["user"]
        self.assertEqual(UserID.from_string(user_id), user)

        # TODO: device_id should come from the macaroon, but currently comes
        # from the db.
        self.assertEqual(user_info["device_id"], "device")

    @defer.inlineCallbacks
    def test_get_guest_user_from_macaroon(self):
        self.store.get_user_by_id = Mock(return_value={"is_guest": True})

        user_id = "@baldrick:matrix.org"
        macaroon = pymacaroons.Macaroon(
            location=self.hs.config.server_name,
            identifier="key",
            key=self.hs.config.macaroon_secret_key,
        )
        macaroon.add_first_party_caveat("gen = 1")
        macaroon.add_first_party_caveat("type = access")
        macaroon.add_first_party_caveat("user_id = %s" % (user_id,))
        macaroon.add_first_party_caveat("guest = true")
        serialized = macaroon.serialize()

        user_info = yield self.auth.get_user_by_access_token(serialized)
        user = user_info["user"]
        is_guest = user_info["is_guest"]
        self.assertEqual(UserID.from_string(user_id), user)
        self.assertTrue(is_guest)
        self.store.get_user_by_id.assert_called_with(user_id)

    @defer.inlineCallbacks
    def test_get_user_from_macaroon_user_db_mismatch(self):
        self.store.get_user_by_access_token = Mock(
            return_value={"name": "@percy:matrix.org"}
        )

        user = "@baldrick:matrix.org"
        macaroon = pymacaroons.Macaroon(
            location=self.hs.config.server_name,
            identifier="key",
            key=self.hs.config.macaroon_secret_key,
        )
        macaroon.add_first_party_caveat("gen = 1")
        macaroon.add_first_party_caveat("type = access")
        macaroon.add_first_party_caveat("user_id = %s" % (user,))
        with self.assertRaises(AuthError) as cm:
            yield self.auth.get_user_by_access_token(macaroon.serialize())
        self.assertEqual(401, cm.exception.code)
        self.assertIn("User mismatch", cm.exception.msg)

    @defer.inlineCallbacks
    def test_get_user_from_macaroon_missing_caveat(self):
        # TODO(danielwh): Remove this mock when we remove the
        # get_user_by_access_token fallback.
        self.store.get_user_by_access_token = Mock(
            return_value={"name": "@baldrick:matrix.org"}
        )

        macaroon = pymacaroons.Macaroon(
            location=self.hs.config.server_name,
            identifier="key",
            key=self.hs.config.macaroon_secret_key,
        )
        macaroon.add_first_party_caveat("gen = 1")
        macaroon.add_first_party_caveat("type = access")

        with self.assertRaises(AuthError) as cm:
            yield self.auth.get_user_by_access_token(macaroon.serialize())
        self.assertEqual(401, cm.exception.code)
        self.assertIn("No user caveat", cm.exception.msg)

    @defer.inlineCallbacks
    def test_get_user_from_macaroon_wrong_key(self):
        # TODO(danielwh): Remove this mock when we remove the
        # get_user_by_access_token fallback.
        self.store.get_user_by_access_token = Mock(
            return_value={"name": "@baldrick:matrix.org"}
        )

        user = "@baldrick:matrix.org"
        macaroon = pymacaroons.Macaroon(
            location=self.hs.config.server_name,
            identifier="key",
            key=self.hs.config.macaroon_secret_key + "wrong",
        )
        macaroon.add_first_party_caveat("gen = 1")
        macaroon.add_first_party_caveat("type = access")
        macaroon.add_first_party_caveat("user_id = %s" % (user,))

        with self.assertRaises(AuthError) as cm:
            yield self.auth.get_user_by_access_token(macaroon.serialize())
        self.assertEqual(401, cm.exception.code)
        self.assertIn("Invalid macaroon", cm.exception.msg)

    @defer.inlineCallbacks
    def test_get_user_from_macaroon_unknown_caveat(self):
        # TODO(danielwh): Remove this mock when we remove the
        # get_user_by_access_token fallback.
        self.store.get_user_by_access_token = Mock(
            return_value={"name": "@baldrick:matrix.org"}
        )

        user = "@baldrick:matrix.org"
        macaroon = pymacaroons.Macaroon(
            location=self.hs.config.server_name,
            identifier="key",
            key=self.hs.config.macaroon_secret_key,
        )
        macaroon.add_first_party_caveat("gen = 1")
        macaroon.add_first_party_caveat("type = access")
        macaroon.add_first_party_caveat("user_id = %s" % (user,))
        macaroon.add_first_party_caveat("cunning > fox")

        with self.assertRaises(AuthError) as cm:
            yield self.auth.get_user_by_access_token(macaroon.serialize())
        self.assertEqual(401, cm.exception.code)
        self.assertIn("Invalid macaroon", cm.exception.msg)

    @defer.inlineCallbacks
    def test_get_user_from_macaroon_expired(self):
        # TODO(danielwh): Remove this mock when we remove the
        # get_user_by_access_token fallback.
        self.store.get_user_by_access_token = Mock(
            return_value={"name": "@baldrick:matrix.org"}
        )

        self.store.get_user_by_access_token = Mock(
            return_value={"name": "@baldrick:matrix.org"}
        )

        user = "@baldrick:matrix.org"
        macaroon = pymacaroons.Macaroon(
            location=self.hs.config.server_name,
            identifier="key",
            key=self.hs.config.macaroon_secret_key,
        )
        macaroon.add_first_party_caveat("gen = 1")
        macaroon.add_first_party_caveat("type = access")
        macaroon.add_first_party_caveat("user_id = %s" % (user,))
        macaroon.add_first_party_caveat("time < -2000")  # ms

        self.hs.clock.now = 5000  # seconds
        self.hs.config.expire_access_token = True
        # yield self.auth.get_user_by_access_token(macaroon.serialize())
        # TODO(daniel): Turn on the check that we validate expiration, when we
        # validate expiration (and remove the above line, which will start
        # throwing).
        with self.assertRaises(AuthError) as cm:
            yield self.auth.get_user_by_access_token(macaroon.serialize())
        self.assertEqual(401, cm.exception.code)
        self.assertIn("Invalid macaroon", cm.exception.msg)

    @defer.inlineCallbacks
    def test_get_user_from_macaroon_with_valid_duration(self):
        # TODO(danielwh): Remove this mock when we remove the
        # get_user_by_access_token fallback.
        self.store.get_user_by_access_token = Mock(
            return_value={"name": "@baldrick:matrix.org"}
        )

        self.store.get_user_by_access_token = Mock(
            return_value={"name": "@baldrick:matrix.org"}
        )

        user_id = "@baldrick:matrix.org"
        macaroon = pymacaroons.Macaroon(
            location=self.hs.config.server_name,
            identifier="key",
            key=self.hs.config.macaroon_secret_key,
        )
        macaroon.add_first_party_caveat("gen = 1")
        macaroon.add_first_party_caveat("type = access")
        macaroon.add_first_party_caveat("user_id = %s" % (user_id,))
        macaroon.add_first_party_caveat("time < 900000000")  # ms

        self.hs.clock.now = 5000  # seconds
        self.hs.config.expire_access_token = True

        user_info = yield self.auth.get_user_by_access_token(macaroon.serialize())
        user = user_info["user"]
        self.assertEqual(UserID.from_string(user_id), user)

    @defer.inlineCallbacks
    def test_cannot_use_regular_token_as_guest(self):
        USER_ID = "@percy:matrix.org"
        self.store.add_access_token_to_user = Mock()

        token = yield self.hs.handlers.auth_handler.issue_access_token(
            USER_ID, "DEVICE"
        )
        self.store.add_access_token_to_user.assert_called_with(USER_ID, token, "DEVICE")

        def get_user(tok):
            if token != tok:
                return None
            return {
                "name": USER_ID,
                "is_guest": False,
                "token_id": 1234,
                "device_id": "DEVICE",
            }

        self.store.get_user_by_access_token = get_user
        self.store.get_user_by_id = Mock(return_value={"is_guest": False})

        # check the token works
        request = Mock(args={})
        request.args[b"access_token"] = [token.encode('ascii')]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        requester = yield self.auth.get_user_by_req(request, allow_guest=True)
        self.assertEqual(UserID.from_string(USER_ID), requester.user)
        self.assertFalse(requester.is_guest)

        # add an is_guest caveat
        mac = pymacaroons.Macaroon.deserialize(token)
        mac.add_first_party_caveat("guest = true")
        guest_tok = mac.serialize()

        # the token should *not* work now
        request = Mock(args={})
        request.args[b"access_token"] = [guest_tok.encode('ascii')]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()

        with self.assertRaises(AuthError) as cm:
            yield self.auth.get_user_by_req(request, allow_guest=True)

        self.assertEqual(401, cm.exception.code)
        self.assertEqual("Guest access token used for regular user", cm.exception.msg)

        self.store.get_user_by_id.assert_called_with(USER_ID)

    @defer.inlineCallbacks
    def test_blocking_mau(self):
        self.hs.config.limit_usage_by_mau = False
        self.hs.config.max_mau_value = 50
        lots_of_users = 100
        small_number_of_users = 1

        # Ensure no error thrown
        yield self.auth.check_auth_blocking()

        self.hs.config.limit_usage_by_mau = True

        self.store.get_monthly_active_count = Mock(
            return_value=defer.succeed(lots_of_users)
        )

        with self.assertRaises(ResourceLimitError) as e:
            yield self.auth.check_auth_blocking()
        self.assertEquals(e.exception.admin_contact, self.hs.config.admin_contact)
        self.assertEquals(e.exception.errcode, Codes.RESOURCE_LIMIT_EXCEEDED)
        self.assertEquals(e.exception.code, 403)

        # Ensure does not throw an error
        self.store.get_monthly_active_count = Mock(
            return_value=defer.succeed(small_number_of_users)
        )
        yield self.auth.check_auth_blocking()

    @defer.inlineCallbacks
    def test_reserved_threepid(self):
        self.hs.config.limit_usage_by_mau = True
        self.hs.config.max_mau_value = 1
        self.store.get_monthly_active_count = lambda: defer.succeed(2)
        threepid = {'medium': 'email', 'address': 'reserved@server.com'}
        unknown_threepid = {'medium': 'email', 'address': 'unreserved@server.com'}
        self.hs.config.mau_limits_reserved_threepids = [threepid]

        yield self.store.register(user_id='user1', token="123", password_hash=None)
        with self.assertRaises(ResourceLimitError):
            yield self.auth.check_auth_blocking()

        with self.assertRaises(ResourceLimitError):
            yield self.auth.check_auth_blocking(threepid=unknown_threepid)

        yield self.auth.check_auth_blocking(threepid=threepid)

    @defer.inlineCallbacks
    def test_hs_disabled(self):
        self.hs.config.hs_disabled = True
        self.hs.config.hs_disabled_message = "Reason for being disabled"
        with self.assertRaises(ResourceLimitError) as e:
            yield self.auth.check_auth_blocking()
        self.assertEquals(e.exception.admin_contact, self.hs.config.admin_contact)
        self.assertEquals(e.exception.errcode, Codes.RESOURCE_LIMIT_EXCEEDED)
        self.assertEquals(e.exception.code, 403)

    @defer.inlineCallbacks
    def test_server_notices_mxid_special_cased(self):
        self.hs.config.hs_disabled = True
        user = "@user:server"
        self.hs.config.server_notices_mxid = user
        self.hs.config.hs_disabled_message = "Reason for being disabled"
        yield self.auth.check_auth_blocking(user)
