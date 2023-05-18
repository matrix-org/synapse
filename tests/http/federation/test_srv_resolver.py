# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2019 New Vector Ltd
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
from typing import Dict, Generator, List, Tuple, cast
from unittest.mock import Mock

from twisted.internet import defer
from twisted.internet.defer import Deferred
from twisted.internet.error import ConnectError
from twisted.names import dns, error

from synapse.http.federation.srv_resolver import Server, SrvResolver
from synapse.logging.context import LoggingContext, current_context

from tests import unittest
from tests.utils import MockClock


class SrvResolverTestCase(unittest.TestCase):
    def test_resolve(self) -> None:
        dns_client_mock = Mock()

        service_name = b"test_service.example.com"
        host_name = b"example.com"

        answer_srv = dns.RRHeader(
            type=dns.SRV, payload=dns.Record_SRV(target=host_name)
        )

        result_deferred: "Deferred[Tuple[List[dns.RRHeader], None, None]]" = Deferred()
        dns_client_mock.lookupService.return_value = result_deferred

        cache: Dict[bytes, List[Server]] = {}
        resolver = SrvResolver(dns_client=dns_client_mock, cache=cache)

        @defer.inlineCallbacks
        def do_lookup() -> Generator["Deferred[object]", object, List[Server]]:
            with LoggingContext("one") as ctx:
                resolve_d = resolver.resolve_service(service_name)
                result: List[Server]
                result = yield defer.ensureDeferred(resolve_d)  # type: ignore[assignment]

                # should have restored our context
                self.assertIs(current_context(), ctx)

                return result

        test_d = do_lookup()
        self.assertNoResult(test_d)

        dns_client_mock.lookupService.assert_called_once_with(service_name)

        result_deferred.callback(([answer_srv], None, None))

        servers = self.successResultOf(test_d)

        self.assertEqual(len(servers), 1)
        self.assertEqual(servers, cache[service_name])
        self.assertEqual(servers[0].host, host_name)

    @defer.inlineCallbacks
    def test_from_cache_expired_and_dns_fail(
        self,
    ) -> Generator["Deferred[object]", object, None]:
        dns_client_mock = Mock()
        dns_client_mock.lookupService.return_value = defer.fail(error.DNSServerError())

        service_name = b"test_service.example.com"

        entry = Mock(spec_set=["expires", "priority", "weight"])
        entry.expires = 0
        entry.priority = 0
        entry.weight = 0

        cache = {service_name: [cast(Server, entry)]}
        resolver = SrvResolver(dns_client=dns_client_mock, cache=cache)

        servers: List[Server]
        servers = yield defer.ensureDeferred(
            resolver.resolve_service(service_name)
        )  # type: ignore[assignment]

        dns_client_mock.lookupService.assert_called_once_with(service_name)

        self.assertEqual(len(servers), 1)
        self.assertEqual(servers, cache[service_name])

    @defer.inlineCallbacks
    def test_from_cache(self) -> Generator["Deferred[object]", object, None]:
        clock = MockClock()

        dns_client_mock = Mock(spec_set=["lookupService"])
        dns_client_mock.lookupService = Mock(spec_set=[])

        service_name = b"test_service.example.com"

        entry = Mock(spec_set=["expires", "priority", "weight"])
        entry.expires = 999999999
        entry.priority = 0
        entry.weight = 0

        cache = {service_name: [cast(Server, entry)]}
        resolver = SrvResolver(
            dns_client=dns_client_mock, cache=cache, get_time=clock.time
        )

        servers: List[Server]
        servers = yield defer.ensureDeferred(
            resolver.resolve_service(service_name)
        )  # type: ignore[assignment]

        self.assertFalse(dns_client_mock.lookupService.called)

        self.assertEqual(len(servers), 1)
        self.assertEqual(servers, cache[service_name])

    @defer.inlineCallbacks
    def test_empty_cache(self) -> Generator["Deferred[object]", object, None]:
        dns_client_mock = Mock()

        dns_client_mock.lookupService.return_value = defer.fail(error.DNSServerError())

        service_name = b"test_service.example.com"

        cache: Dict[bytes, List[Server]] = {}
        resolver = SrvResolver(dns_client=dns_client_mock, cache=cache)

        with self.assertRaises(error.DNSServerError):
            yield defer.ensureDeferred(resolver.resolve_service(service_name))

    @defer.inlineCallbacks
    def test_name_error(self) -> Generator["Deferred[object]", object, None]:
        dns_client_mock = Mock()

        dns_client_mock.lookupService.return_value = defer.fail(error.DNSNameError())

        service_name = b"test_service.example.com"

        cache: Dict[bytes, List[Server]] = {}
        resolver = SrvResolver(dns_client=dns_client_mock, cache=cache)

        servers: List[Server]
        servers = yield defer.ensureDeferred(
            resolver.resolve_service(service_name)
        )  # type: ignore[assignment]

        self.assertEqual(len(servers), 0)
        self.assertEqual(len(cache), 0)

    def test_disabled_service(self) -> None:
        """
        test the behaviour when there is a single record which is ".".
        """
        service_name = b"test_service.example.com"

        lookup_deferred: "Deferred[Tuple[List[dns.RRHeader], None, None]]" = Deferred()
        dns_client_mock = Mock()
        dns_client_mock.lookupService.return_value = lookup_deferred
        cache: Dict[bytes, List[Server]] = {}
        resolver = SrvResolver(dns_client=dns_client_mock, cache=cache)

        # Old versions of Twisted don't have an ensureDeferred in failureResultOf.
        resolve_d = defer.ensureDeferred(resolver.resolve_service(service_name))

        # returning a single "." should make the lookup fail with a ConenctError
        lookup_deferred.callback(
            (
                [dns.RRHeader(type=dns.SRV, payload=dns.Record_SRV(target=b"."))],
                None,
                None,
            )
        )

        self.failureResultOf(resolve_d, ConnectError)

    def test_non_srv_answer(self) -> None:
        """
        test the behaviour when the dns server gives us a spurious non-SRV response
        """
        service_name = b"test_service.example.com"

        lookup_deferred: "Deferred[Tuple[List[dns.RRHeader], None, None]]" = Deferred()
        dns_client_mock = Mock()
        dns_client_mock.lookupService.return_value = lookup_deferred
        cache: Dict[bytes, List[Server]] = {}
        resolver = SrvResolver(dns_client=dns_client_mock, cache=cache)

        # Old versions of Twisted don't have an ensureDeferred in successResultOf.
        resolve_d = defer.ensureDeferred(resolver.resolve_service(service_name))

        lookup_deferred.callback(
            (
                [
                    dns.RRHeader(type=dns.A, payload=dns.Record_A()),
                    dns.RRHeader(type=dns.SRV, payload=dns.Record_SRV(target=b"host")),
                ],
                None,
                None,
            )
        )

        servers = self.successResultOf(resolve_d)

        self.assertEqual(len(servers), 1)
        self.assertEqual(servers, cache[service_name])
        self.assertEqual(servers[0].host, b"host")
