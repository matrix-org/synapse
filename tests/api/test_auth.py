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

from unittest.mock import AsyncMock, Mock

import pymacaroons

from twisted.test.proto_helpers import MemoryReactor

from synapse.api.auth.internal import InternalAuth
from synapse.api.auth_blocking import AuthBlocking
from synapse.api.constants import UserTypes
from synapse.api.errors import (
    AuthError,
    Codes,
    InvalidClientTokenError,
    MissingClientTokenError,
    ResourceLimitError,
)
from synapse.appservice import ApplicationService
from synapse.server import HomeServer
from synapse.storage.databases.main.registration import TokenLookupResult
from synapse.types import Requester, UserID
from synapse.util import Clock

from tests import unittest
from tests.unittest import override_config
from tests.utils import mock_getRawHeaders


class AuthTestCase(unittest.HomeserverTestCase):
    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = Mock()

        # type-ignore: datastores is None until hs.setup() is called---but it'll
        # have been called by the HomeserverTestCase machinery.
        hs.datastores.main = self.store  # type: ignore[union-attr]
        hs.get_auth_handler().store = self.store
        self.auth = InternalAuth(hs)

        # AuthBlocking reads from the hs' config on initialization. We need to
        # modify its config instead of the hs'
        self.auth_blocking = AuthBlocking(hs)

        self.test_user = "@foo:bar"
        self.test_token = b"_test_token_"

        # this is overridden for the appservice tests
        self.store.get_app_service_by_token = Mock(return_value=None)

        self.store.insert_client_ip = AsyncMock(return_value=None)
        self.store.is_support_user = AsyncMock(return_value=False)

    def test_get_user_by_req_user_valid_token(self) -> None:
        user_info = TokenLookupResult(
            user_id=self.test_user, token_id=5, device_id="device"
        )
        self.store.get_user_by_access_token = AsyncMock(return_value=user_info)
        self.store.mark_access_token_as_used = AsyncMock(return_value=None)
        self.store.get_user_locked_status = AsyncMock(return_value=False)

        request = Mock(args={})
        request.args[b"access_token"] = [self.test_token]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        requester = self.get_success(self.auth.get_user_by_req(request))
        self.assertEqual(requester.user.to_string(), self.test_user)

    def test_get_user_by_req_user_bad_token(self) -> None:
        self.store.get_user_by_access_token = AsyncMock(return_value=None)

        request = Mock(args={})
        request.args[b"access_token"] = [self.test_token]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        f = self.get_failure(
            self.auth.get_user_by_req(request), InvalidClientTokenError
        ).value
        self.assertEqual(f.code, 401)
        self.assertEqual(f.errcode, "M_UNKNOWN_TOKEN")

    def test_get_user_by_req_user_missing_token(self) -> None:
        user_info = TokenLookupResult(user_id=self.test_user, token_id=5)
        self.store.get_user_by_access_token = AsyncMock(return_value=user_info)

        request = Mock(args={})
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        f = self.get_failure(
            self.auth.get_user_by_req(request), MissingClientTokenError
        ).value
        self.assertEqual(f.code, 401)
        self.assertEqual(f.errcode, "M_MISSING_TOKEN")

    def test_get_user_by_req_appservice_valid_token(self) -> None:
        app_service = Mock(
            token="foobar", url="a_url", sender=self.test_user, ip_range_whitelist=None
        )
        self.store.get_app_service_by_token = Mock(return_value=app_service)
        self.store.get_user_by_access_token = AsyncMock(return_value=None)

        request = Mock(args={})
        request.getClientAddress.return_value.host = "127.0.0.1"
        request.args[b"access_token"] = [self.test_token]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        requester = self.get_success(self.auth.get_user_by_req(request))
        self.assertEqual(requester.user.to_string(), self.test_user)

    def test_get_user_by_req_appservice_valid_token_good_ip(self) -> None:
        from netaddr import IPSet

        app_service = Mock(
            token="foobar",
            url="a_url",
            sender=self.test_user,
            ip_range_whitelist=IPSet(["192.168/16"]),
        )
        self.store.get_app_service_by_token = Mock(return_value=app_service)
        self.store.get_user_by_access_token = AsyncMock(return_value=None)

        request = Mock(args={})
        request.getClientAddress.return_value.host = "192.168.10.10"
        request.args[b"access_token"] = [self.test_token]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        requester = self.get_success(self.auth.get_user_by_req(request))
        self.assertEqual(requester.user.to_string(), self.test_user)

    def test_get_user_by_req_appservice_valid_token_bad_ip(self) -> None:
        from netaddr import IPSet

        app_service = Mock(
            token="foobar",
            url="a_url",
            sender=self.test_user,
            ip_range_whitelist=IPSet(["192.168/16"]),
        )
        self.store.get_app_service_by_token = Mock(return_value=app_service)
        self.store.get_user_by_access_token = AsyncMock(return_value=None)

        request = Mock(args={})
        request.getClientAddress.return_value.host = "131.111.8.42"
        request.args[b"access_token"] = [self.test_token]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        f = self.get_failure(
            self.auth.get_user_by_req(request), InvalidClientTokenError
        ).value
        self.assertEqual(f.code, 401)
        self.assertEqual(f.errcode, "M_UNKNOWN_TOKEN")

    def test_get_user_by_req_appservice_bad_token(self) -> None:
        self.store.get_app_service_by_token = Mock(return_value=None)
        self.store.get_user_by_access_token = AsyncMock(return_value=None)

        request = Mock(args={})
        request.args[b"access_token"] = [self.test_token]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        f = self.get_failure(
            self.auth.get_user_by_req(request), InvalidClientTokenError
        ).value
        self.assertEqual(f.code, 401)
        self.assertEqual(f.errcode, "M_UNKNOWN_TOKEN")

    def test_get_user_by_req_appservice_missing_token(self) -> None:
        app_service = Mock(token="foobar", url="a_url", sender=self.test_user)
        self.store.get_app_service_by_token = Mock(return_value=app_service)
        self.store.get_user_by_access_token = AsyncMock(return_value=None)

        request = Mock(args={})
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        f = self.get_failure(
            self.auth.get_user_by_req(request), MissingClientTokenError
        ).value
        self.assertEqual(f.code, 401)
        self.assertEqual(f.errcode, "M_MISSING_TOKEN")

    def test_get_user_by_req_appservice_valid_token_valid_user_id(self) -> None:
        masquerading_user_id = b"@doppelganger:matrix.org"
        app_service = Mock(
            token="foobar", url="a_url", sender=self.test_user, ip_range_whitelist=None
        )
        app_service.is_interested_in_user = Mock(return_value=True)
        self.store.get_app_service_by_token = Mock(return_value=app_service)

        class FakeUserInfo:
            is_guest = False

        self.store.get_user_by_id = AsyncMock(return_value=FakeUserInfo())
        self.store.get_user_by_access_token = AsyncMock(return_value=None)

        request = Mock(args={})
        request.getClientAddress.return_value.host = "127.0.0.1"
        request.args[b"access_token"] = [self.test_token]
        request.args[b"user_id"] = [masquerading_user_id]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        requester = self.get_success(self.auth.get_user_by_req(request))
        self.assertEqual(
            requester.user.to_string(), masquerading_user_id.decode("utf8")
        )

    def test_get_user_by_req_appservice_valid_token_bad_user_id(self) -> None:
        masquerading_user_id = b"@doppelganger:matrix.org"
        app_service = Mock(
            token="foobar", url="a_url", sender=self.test_user, ip_range_whitelist=None
        )
        app_service.is_interested_in_user = Mock(return_value=False)
        self.store.get_app_service_by_token = Mock(return_value=app_service)
        self.store.get_user_by_access_token = AsyncMock(return_value=None)

        request = Mock(args={})
        request.getClientAddress.return_value.host = "127.0.0.1"
        request.args[b"access_token"] = [self.test_token]
        request.args[b"user_id"] = [masquerading_user_id]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        self.get_failure(self.auth.get_user_by_req(request), AuthError)

    @override_config({"experimental_features": {"msc3202_device_masquerading": True}})
    def test_get_user_by_req_appservice_valid_token_valid_device_id(self) -> None:
        """
        Tests that when an application service passes the device_id URL parameter
        with the ID of a valid device for the user in question,
        the requester instance tracks that device ID.
        """
        masquerading_user_id = b"@doppelganger:matrix.org"
        masquerading_device_id = b"DOPPELDEVICE"
        app_service = Mock(
            token="foobar", url="a_url", sender=self.test_user, ip_range_whitelist=None
        )
        app_service.is_interested_in_user = Mock(return_value=True)
        self.store.get_app_service_by_token = Mock(return_value=app_service)
        # This just needs to return a truth-y value.
        self.store.get_user_by_id = AsyncMock(return_value={"is_guest": False})
        self.store.get_user_by_access_token = AsyncMock(return_value=None)
        # This also needs to just return a truth-y value
        self.store.get_device = AsyncMock(return_value={"hidden": False})

        request = Mock(args={})
        request.getClientAddress.return_value.host = "127.0.0.1"
        request.args[b"access_token"] = [self.test_token]
        request.args[b"user_id"] = [masquerading_user_id]
        request.args[b"org.matrix.msc3202.device_id"] = [masquerading_device_id]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        requester = self.get_success(self.auth.get_user_by_req(request))
        self.assertEqual(
            requester.user.to_string(), masquerading_user_id.decode("utf8")
        )
        self.assertEqual(requester.device_id, masquerading_device_id.decode("utf8"))

    @override_config({"experimental_features": {"msc3202_device_masquerading": True}})
    def test_get_user_by_req_appservice_valid_token_invalid_device_id(self) -> None:
        """
        Tests that when an application service passes the device_id URL parameter
        with an ID that is not a valid device ID for the user in question,
        the request fails with the appropriate error code.
        """
        masquerading_user_id = b"@doppelganger:matrix.org"
        masquerading_device_id = b"NOT_A_REAL_DEVICE_ID"
        app_service = Mock(
            token="foobar", url="a_url", sender=self.test_user, ip_range_whitelist=None
        )
        app_service.is_interested_in_user = Mock(return_value=True)
        self.store.get_app_service_by_token = Mock(return_value=app_service)
        # This just needs to return a truth-y value.
        self.store.get_user_by_id = AsyncMock(return_value={"is_guest": False})
        self.store.get_user_by_access_token = AsyncMock(return_value=None)
        # This also needs to just return a falsey value
        self.store.get_device = AsyncMock(return_value=None)

        request = Mock(args={})
        request.getClientAddress.return_value.host = "127.0.0.1"
        request.args[b"access_token"] = [self.test_token]
        request.args[b"user_id"] = [masquerading_user_id]
        request.args[b"org.matrix.msc3202.device_id"] = [masquerading_device_id]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()

        failure = self.get_failure(self.auth.get_user_by_req(request), AuthError)
        self.assertEqual(failure.value.code, 400)
        self.assertEqual(failure.value.errcode, Codes.EXCLUSIVE)

    def test_get_user_by_req__puppeted_token__not_tracking_puppeted_mau(self) -> None:
        self.store.get_user_by_access_token = AsyncMock(
            return_value=TokenLookupResult(
                user_id="@baldrick:matrix.org",
                device_id="device",
                token_id=5,
                token_owner="@admin:matrix.org",
                token_used=True,
            )
        )
        self.store.insert_client_ip = AsyncMock(return_value=None)
        self.store.mark_access_token_as_used = AsyncMock(return_value=None)
        self.store.get_user_locked_status = AsyncMock(return_value=False)
        request = Mock(args={})
        request.getClientAddress.return_value.host = "127.0.0.1"
        request.args[b"access_token"] = [self.test_token]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        self.get_success(self.auth.get_user_by_req(request))
        self.store.insert_client_ip.assert_called_once()

    def test_get_user_by_req__puppeted_token__tracking_puppeted_mau(self) -> None:
        self.auth._track_puppeted_user_ips = True
        self.store.get_user_by_access_token = AsyncMock(
            return_value=TokenLookupResult(
                user_id="@baldrick:matrix.org",
                device_id="device",
                token_id=5,
                token_owner="@admin:matrix.org",
                token_used=True,
            )
        )
        self.store.get_user_locked_status = AsyncMock(return_value=False)
        self.store.insert_client_ip = AsyncMock(return_value=None)
        self.store.mark_access_token_as_used = AsyncMock(return_value=None)
        request = Mock(args={})
        request.getClientAddress.return_value.host = "127.0.0.1"
        request.args[b"access_token"] = [self.test_token]
        request.requestHeaders.getRawHeaders = mock_getRawHeaders()
        self.get_success(self.auth.get_user_by_req(request))
        self.assertEqual(self.store.insert_client_ip.call_count, 2)

    def test_get_user_from_macaroon(self) -> None:
        self.store.get_user_by_access_token = AsyncMock(return_value=None)

        user_id = "@baldrick:matrix.org"
        macaroon = pymacaroons.Macaroon(
            location=self.hs.config.server.server_name,
            identifier="key",
            key=self.hs.config.key.macaroon_secret_key,
        )
        # "Legacy" macaroons should not work for regular users not in the database
        macaroon.add_first_party_caveat("gen = 1")
        macaroon.add_first_party_caveat("type = access")
        macaroon.add_first_party_caveat("user_id = %s" % (user_id,))
        serialized = macaroon.serialize()
        self.get_failure(
            self.auth.get_user_by_access_token(serialized), InvalidClientTokenError
        )

    def test_get_guest_user_from_macaroon(self) -> None:
        class FakeUserInfo:
            is_guest = True

        self.store.get_user_by_id = AsyncMock(return_value=FakeUserInfo())
        self.store.get_user_by_access_token = AsyncMock(return_value=None)

        user_id = "@baldrick:matrix.org"
        macaroon = pymacaroons.Macaroon(
            location=self.hs.config.server.server_name,
            identifier="key",
            key=self.hs.config.key.macaroon_secret_key,
        )
        macaroon.add_first_party_caveat("gen = 1")
        macaroon.add_first_party_caveat("type = access")
        macaroon.add_first_party_caveat("user_id = %s" % (user_id,))
        macaroon.add_first_party_caveat("guest = true")
        serialized = macaroon.serialize()

        user_info = self.get_success(self.auth.get_user_by_access_token(serialized))
        self.assertEqual(user_id, user_info.user.to_string())
        self.assertTrue(user_info.is_guest)
        self.store.get_user_by_id.assert_called_with(user_id)

    def test_blocking_mau(self) -> None:
        self.auth_blocking._limit_usage_by_mau = False
        self.auth_blocking._max_mau_value = 50
        lots_of_users = 100
        small_number_of_users = 1

        # Ensure no error thrown
        self.get_success(self.auth_blocking.check_auth_blocking())

        self.auth_blocking._limit_usage_by_mau = True

        self.store.get_monthly_active_count = AsyncMock(return_value=lots_of_users)

        e = self.get_failure(
            self.auth_blocking.check_auth_blocking(), ResourceLimitError
        )
        self.assertEqual(e.value.admin_contact, self.hs.config.server.admin_contact)
        self.assertEqual(e.value.errcode, Codes.RESOURCE_LIMIT_EXCEEDED)
        self.assertEqual(e.value.code, 403)

        # Ensure does not throw an error
        self.store.get_monthly_active_count = AsyncMock(
            return_value=small_number_of_users
        )
        self.get_success(self.auth_blocking.check_auth_blocking())

    def test_blocking_mau__depending_on_user_type(self) -> None:
        self.auth_blocking._max_mau_value = 50
        self.auth_blocking._limit_usage_by_mau = True

        self.store.get_monthly_active_count = AsyncMock(return_value=100)
        # Support users allowed
        self.get_success(
            self.auth_blocking.check_auth_blocking(user_type=UserTypes.SUPPORT)
        )
        self.store.get_monthly_active_count = AsyncMock(return_value=100)
        # Bots not allowed
        self.get_failure(
            self.auth_blocking.check_auth_blocking(user_type=UserTypes.BOT),
            ResourceLimitError,
        )
        self.store.get_monthly_active_count = AsyncMock(return_value=100)
        # Real users not allowed
        self.get_failure(self.auth_blocking.check_auth_blocking(), ResourceLimitError)

    def test_blocking_mau__appservice_requester_allowed_when_not_tracking_ips(
        self,
    ) -> None:
        self.auth_blocking._max_mau_value = 50
        self.auth_blocking._limit_usage_by_mau = True
        self.auth_blocking._track_appservice_user_ips = False

        self.store.get_monthly_active_count = AsyncMock(return_value=100)
        self.store.user_last_seen_monthly_active = AsyncMock(return_value=None)
        self.store.is_trial_user = AsyncMock(return_value=False)

        appservice = ApplicationService(
            "abcd",
            id="1234",
            namespaces={
                "users": [{"regex": "@_appservice.*:sender", "exclusive": True}]
            },
            sender="@appservice:sender",
        )
        requester = Requester(
            user=UserID.from_string("@appservice:server"),
            access_token_id=None,
            device_id="FOOBAR",
            is_guest=False,
            scope=set(),
            shadow_banned=False,
            app_service=appservice,
            authenticated_entity="@appservice:server",
        )
        self.get_success(self.auth_blocking.check_auth_blocking(requester=requester))

    def test_blocking_mau__appservice_requester_disallowed_when_tracking_ips(
        self,
    ) -> None:
        self.auth_blocking._max_mau_value = 50
        self.auth_blocking._limit_usage_by_mau = True
        self.auth_blocking._track_appservice_user_ips = True

        self.store.get_monthly_active_count = AsyncMock(return_value=100)
        self.store.user_last_seen_monthly_active = AsyncMock(return_value=None)
        self.store.is_trial_user = AsyncMock(return_value=False)

        appservice = ApplicationService(
            "abcd",
            id="1234",
            namespaces={
                "users": [{"regex": "@_appservice.*:sender", "exclusive": True}]
            },
            sender="@appservice:sender",
        )
        requester = Requester(
            user=UserID.from_string("@appservice:server"),
            access_token_id=None,
            device_id="FOOBAR",
            is_guest=False,
            scope=set(),
            shadow_banned=False,
            app_service=appservice,
            authenticated_entity="@appservice:server",
        )
        self.get_failure(
            self.auth_blocking.check_auth_blocking(requester=requester),
            ResourceLimitError,
        )

    def test_reserved_threepid(self) -> None:
        self.auth_blocking._limit_usage_by_mau = True
        self.auth_blocking._max_mau_value = 1
        self.store.get_monthly_active_count = AsyncMock(return_value=2)
        threepid = {"medium": "email", "address": "reserved@server.com"}
        unknown_threepid = {"medium": "email", "address": "unreserved@server.com"}
        self.auth_blocking._mau_limits_reserved_threepids = [threepid]

        self.get_failure(self.auth_blocking.check_auth_blocking(), ResourceLimitError)

        self.get_failure(
            self.auth_blocking.check_auth_blocking(threepid=unknown_threepid),
            ResourceLimitError,
        )

        self.get_success(self.auth_blocking.check_auth_blocking(threepid=threepid))

    def test_hs_disabled(self) -> None:
        self.auth_blocking._hs_disabled = True
        self.auth_blocking._hs_disabled_message = "Reason for being disabled"
        e = self.get_failure(
            self.auth_blocking.check_auth_blocking(), ResourceLimitError
        )
        self.assertEqual(e.value.admin_contact, self.hs.config.server.admin_contact)
        self.assertEqual(e.value.errcode, Codes.RESOURCE_LIMIT_EXCEEDED)
        self.assertEqual(e.value.code, 403)

    def test_hs_disabled_no_server_notices_user(self) -> None:
        """Check that 'hs_disabled_message' works correctly when there is no
        server_notices user.
        """
        # this should be the default, but we had a bug where the test was doing the wrong
        # thing, so let's make it explicit
        self.auth_blocking._server_notices_mxid = None

        self.auth_blocking._hs_disabled = True
        self.auth_blocking._hs_disabled_message = "Reason for being disabled"
        e = self.get_failure(
            self.auth_blocking.check_auth_blocking(), ResourceLimitError
        )
        self.assertEqual(e.value.admin_contact, self.hs.config.server.admin_contact)
        self.assertEqual(e.value.errcode, Codes.RESOURCE_LIMIT_EXCEEDED)
        self.assertEqual(e.value.code, 403)

    def test_server_notices_mxid_special_cased(self) -> None:
        self.auth_blocking._hs_disabled = True
        user = "@user:server"
        self.auth_blocking._server_notices_mxid = user
        self.auth_blocking._hs_disabled_message = "Reason for being disabled"
        self.get_success(self.auth_blocking.check_auth_blocking(user))
