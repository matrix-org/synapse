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

from unittest.mock import Mock

import pymacaroons

from synapse.api.auth import Auth
from synapse.api.constants import UserTypes
from synapse.api.errors import (
    AuthError,
    Codes,
    InvalidClientCredentialsError,
    InvalidClientTokenError,
    MissingClientTokenError,
    ResourceLimitError,
)
from synapse.storage.databases.main.registration import TokenLookupResult
from synapse.types import UserID

from tests import unittest
from tests.test_utils import simple_async_mock
from tests.utils import mock_getRawHeaders


class AuthTestCase(unittest.HomeserverTestCase):
    def prepare(self, reactor, clock, hs):
        self.store = Mock()

        hs.get_datastore = Mock(return_value=self.store)
        hs.get_auth_handler().store = self.store
        self.auth = Auth(hs)

        # AuthBlocking reads from the hs' config on initialization. We need to
        # modify its config instead of the hs'
        self.auth_blocking = self.auth._auth_blocking

        self.test_user = "@foo:bar"
        self.test_token = b"_test_token_"

        # this is overridden for the appservice tests
        self.store.get_app_service_by_token = Mock(return_value=None)

        self.store.insert_client_ip = simple_async_mock(None)
        self.store.is_support_user = simple_async_mock(False)

    def test_get_user_by_req_user_valid_token(self):
        user_info = TokenLookupResult(
            user_id=self.test_user, token_id=5, device_id="device"
        )
        self.store.get_user_by_access_token = simple_async_mock(user_info)

        request = Mock(args={})
        request.args[b"access_token"] = [self.test_token]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        requester = self.get_success(self.auth.get_user_by_req(request))
        self.assertEquals(requester.user.to_string(), self.test_user)

    def test_get_user_by_req_user_bad_token(self):
        self.store.get_user_by_access_token = simple_async_mock(None)

        request = Mock(args={})
        request.args[b"access_token"] = [self.test_token]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        f = self.get_failure(
            self.auth.get_user_by_req(request), InvalidClientTokenError
        ).value
        self.assertEqual(f.code, 401)
        self.assertEqual(f.errcode, "M_UNKNOWN_TOKEN")

    def test_get_user_by_req_user_missing_token(self):
        user_info = TokenLookupResult(user_id=self.test_user, token_id=5)
        self.store.get_user_by_access_token = simple_async_mock(user_info)

        request = Mock(args={})
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        f = self.get_failure(
            self.auth.get_user_by_req(request), MissingClientTokenError
        ).value
        self.assertEqual(f.code, 401)
        self.assertEqual(f.errcode, "M_MISSING_TOKEN")

    def test_get_user_by_req_appservice_valid_token(self):
        app_service = Mock(
            token="foobar", url="a_url", sender=self.test_user, ip_range_whitelist=None
        )
        self.store.get_app_service_by_token = Mock(return_value=app_service)
        self.store.get_user_by_access_token = simple_async_mock(None)

        request = Mock(args={})
        request.getClientIP.return_value = "127.0.0.1"
        request.args[b"access_token"] = [self.test_token]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        requester = self.get_success(self.auth.get_user_by_req(request))
        self.assertEquals(requester.user.to_string(), self.test_user)

    def test_get_user_by_req_appservice_valid_token_good_ip(self):
        from netaddr import IPSet

        app_service = Mock(
            token="foobar",
            url="a_url",
            sender=self.test_user,
            ip_range_whitelist=IPSet(["192.168/16"]),
        )
        self.store.get_app_service_by_token = Mock(return_value=app_service)
        self.store.get_user_by_access_token = simple_async_mock(None)

        request = Mock(args={})
        request.getClientIP.return_value = "192.168.10.10"
        request.args[b"access_token"] = [self.test_token]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        requester = self.get_success(self.auth.get_user_by_req(request))
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
        self.store.get_user_by_access_token = simple_async_mock(None)

        request = Mock(args={})
        request.getClientIP.return_value = "131.111.8.42"
        request.args[b"access_token"] = [self.test_token]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        f = self.get_failure(
            self.auth.get_user_by_req(request), InvalidClientTokenError
        ).value
        self.assertEqual(f.code, 401)
        self.assertEqual(f.errcode, "M_UNKNOWN_TOKEN")

    def test_get_user_by_req_appservice_bad_token(self):
        self.store.get_app_service_by_token = Mock(return_value=None)
        self.store.get_user_by_access_token = simple_async_mock(None)

        request = Mock(args={})
        request.args[b"access_token"] = [self.test_token]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        f = self.get_failure(
            self.auth.get_user_by_req(request), InvalidClientTokenError
        ).value
        self.assertEqual(f.code, 401)
        self.assertEqual(f.errcode, "M_UNKNOWN_TOKEN")

    def test_get_user_by_req_appservice_missing_token(self):
        app_service = Mock(token="foobar", url="a_url", sender=self.test_user)
        self.store.get_app_service_by_token = Mock(return_value=app_service)
        self.store.get_user_by_access_token = simple_async_mock(None)

        request = Mock(args={})
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        f = self.get_failure(
            self.auth.get_user_by_req(request), MissingClientTokenError
        ).value
        self.assertEqual(f.code, 401)
        self.assertEqual(f.errcode, "M_MISSING_TOKEN")

    def test_get_user_by_req_appservice_valid_token_valid_user_id(self):
        masquerading_user_id = b"@doppelganger:matrix.org"
        app_service = Mock(
            token="foobar", url="a_url", sender=self.test_user, ip_range_whitelist=None
        )
        app_service.is_interested_in_user = Mock(return_value=True)
        self.store.get_app_service_by_token = Mock(return_value=app_service)
        # This just needs to return a truth-y value.
        self.store.get_user_by_id = simple_async_mock({"is_guest": False})
        self.store.get_user_by_access_token = simple_async_mock(None)

        request = Mock(args={})
        request.getClientIP.return_value = "127.0.0.1"
        request.args[b"access_token"] = [self.test_token]
        request.args[b"user_id"] = [masquerading_user_id]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        requester = self.get_success(self.auth.get_user_by_req(request))
        self.assertEquals(
            requester.user.to_string(), masquerading_user_id.decode("utf8")
        )

    def test_get_user_by_req_appservice_valid_token_bad_user_id(self):
        masquerading_user_id = b"@doppelganger:matrix.org"
        app_service = Mock(
            token="foobar", url="a_url", sender=self.test_user, ip_range_whitelist=None
        )
        app_service.is_interested_in_user = Mock(return_value=False)
        self.store.get_app_service_by_token = Mock(return_value=app_service)
        self.store.get_user_by_access_token = simple_async_mock(None)

        request = Mock(args={})
        request.getClientIP.return_value = "127.0.0.1"
        request.args[b"access_token"] = [self.test_token]
        request.args[b"user_id"] = [masquerading_user_id]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        self.get_failure(self.auth.get_user_by_req(request), AuthError)

    def test_get_user_from_macaroon(self):
        self.store.get_user_by_access_token = simple_async_mock(
            TokenLookupResult(user_id="@baldrick:matrix.org", device_id="device")
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
        user_info = self.get_success(
            self.auth.get_user_by_access_token(macaroon.serialize())
        )
        self.assertEqual(user_id, user_info.user_id)

        # TODO: device_id should come from the macaroon, but currently comes
        # from the db.
        self.assertEqual(user_info.device_id, "device")

    def test_get_guest_user_from_macaroon(self):
        self.store.get_user_by_id = simple_async_mock({"is_guest": True})
        self.store.get_user_by_access_token = simple_async_mock(None)

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

        user_info = self.get_success(self.auth.get_user_by_access_token(serialized))
        self.assertEqual(user_id, user_info.user_id)
        self.assertTrue(user_info.is_guest)
        self.store.get_user_by_id.assert_called_with(user_id)

    def test_cannot_use_regular_token_as_guest(self):
        USER_ID = "@percy:matrix.org"
        self.store.add_access_token_to_user = simple_async_mock(None)
        self.store.get_device = simple_async_mock(None)

        token = self.get_success(
            self.hs.get_auth_handler().get_access_token_for_user_id(
                USER_ID, "DEVICE", valid_until_ms=None
            )
        )
        self.store.add_access_token_to_user.assert_called_with(
            user_id=USER_ID,
            token=token,
            device_id="DEVICE",
            valid_until_ms=None,
            puppets_user_id=None,
        )

        async def get_user(tok):
            if token != tok:
                return None
            return TokenLookupResult(
                user_id=USER_ID,
                is_guest=False,
                token_id=1234,
                device_id="DEVICE",
            )

        self.store.get_user_by_access_token = get_user
        self.store.get_user_by_id = simple_async_mock({"is_guest": False})

        # check the token works
        request = Mock(args={})
        request.args[b"access_token"] = [token.encode("ascii")]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        requester = self.get_success(
            self.auth.get_user_by_req(request, allow_guest=True)
        )
        self.assertEqual(UserID.from_string(USER_ID), requester.user)
        self.assertFalse(requester.is_guest)

        # add an is_guest caveat
        mac = pymacaroons.Macaroon.deserialize(token)
        mac.add_first_party_caveat("guest = true")
        guest_tok = mac.serialize()

        # the token should *not* work now
        request = Mock(args={})
        request.args[b"access_token"] = [guest_tok.encode("ascii")]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()

        cm = self.get_failure(
            self.auth.get_user_by_req(request, allow_guest=True),
            InvalidClientCredentialsError,
        )

        self.assertEqual(401, cm.value.code)
        self.assertEqual("Guest access token used for regular user", cm.value.msg)

        self.store.get_user_by_id.assert_called_with(USER_ID)

    def test_blocking_mau(self):
        self.auth_blocking._limit_usage_by_mau = False
        self.auth_blocking._max_mau_value = 50
        lots_of_users = 100
        small_number_of_users = 1

        # Ensure no error thrown
        self.get_success(self.auth.check_auth_blocking())

        self.auth_blocking._limit_usage_by_mau = True

        self.store.get_monthly_active_count = simple_async_mock(lots_of_users)

        e = self.get_failure(self.auth.check_auth_blocking(), ResourceLimitError)
        self.assertEquals(e.value.admin_contact, self.hs.config.admin_contact)
        self.assertEquals(e.value.errcode, Codes.RESOURCE_LIMIT_EXCEEDED)
        self.assertEquals(e.value.code, 403)

        # Ensure does not throw an error
        self.store.get_monthly_active_count = simple_async_mock(small_number_of_users)
        self.get_success(self.auth.check_auth_blocking())

    def test_blocking_mau__depending_on_user_type(self):
        self.auth_blocking._max_mau_value = 50
        self.auth_blocking._limit_usage_by_mau = True

        self.store.get_monthly_active_count = simple_async_mock(100)
        # Support users allowed
        self.get_success(self.auth.check_auth_blocking(user_type=UserTypes.SUPPORT))
        self.store.get_monthly_active_count = simple_async_mock(100)
        # Bots not allowed
        self.get_failure(
            self.auth.check_auth_blocking(user_type=UserTypes.BOT), ResourceLimitError
        )
        self.store.get_monthly_active_count = simple_async_mock(100)
        # Real users not allowed
        self.get_failure(self.auth.check_auth_blocking(), ResourceLimitError)

    def test_reserved_threepid(self):
        self.auth_blocking._limit_usage_by_mau = True
        self.auth_blocking._max_mau_value = 1
        self.store.get_monthly_active_count = simple_async_mock(2)
        threepid = {"medium": "email", "address": "reserved@server.com"}
        unknown_threepid = {"medium": "email", "address": "unreserved@server.com"}
        self.auth_blocking._mau_limits_reserved_threepids = [threepid]

        self.get_failure(self.auth.check_auth_blocking(), ResourceLimitError)

        self.get_failure(
            self.auth.check_auth_blocking(threepid=unknown_threepid), ResourceLimitError
        )

        self.get_success(self.auth.check_auth_blocking(threepid=threepid))

    def test_hs_disabled(self):
        self.auth_blocking._hs_disabled = True
        self.auth_blocking._hs_disabled_message = "Reason for being disabled"
        e = self.get_failure(self.auth.check_auth_blocking(), ResourceLimitError)
        self.assertEquals(e.value.admin_contact, self.hs.config.admin_contact)
        self.assertEquals(e.value.errcode, Codes.RESOURCE_LIMIT_EXCEEDED)
        self.assertEquals(e.value.code, 403)

    def test_hs_disabled_no_server_notices_user(self):
        """Check that 'hs_disabled_message' works correctly when there is no
        server_notices user.
        """
        # this should be the default, but we had a bug where the test was doing the wrong
        # thing, so let's make it explicit
        self.auth_blocking._server_notices_mxid = None

        self.auth_blocking._hs_disabled = True
        self.auth_blocking._hs_disabled_message = "Reason for being disabled"
        e = self.get_failure(self.auth.check_auth_blocking(), ResourceLimitError)
        self.assertEquals(e.value.admin_contact, self.hs.config.admin_contact)
        self.assertEquals(e.value.errcode, Codes.RESOURCE_LIMIT_EXCEEDED)
        self.assertEquals(e.value.code, 403)

    def test_server_notices_mxid_special_cased(self):
        self.auth_blocking._hs_disabled = True
        user = "@user:server"
        self.auth_blocking._server_notices_mxid = user
        self.auth_blocking._hs_disabled_message = "Reason for being disabled"
        self.get_success(self.auth.check_auth_blocking(user))
