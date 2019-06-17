# -*- coding: utf-8 -*-
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

from mock import Mock

from twisted.internet import defer
from twisted.internet.defer import Deferred
from twisted.internet.error import ConnectError
from twisted.names import dns, error

from synapse.http.federation.srv_resolver import SrvResolver
from synapse.util.logcontext import LoggingContext

from tests import unittest
from tests.utils import MockClock


class SrvResolverTestCase(unittest.TestCase):
    def test_resolve(self):
        dns_client_mock = Mock()

        service_name = b"test_service.example.com"
        host_name = b"example.com"

        answer_srv = dns.RRHeader(
            type=dns.SRV, payload=dns.Record_SRV(target=host_name)
        )

        result_deferred = Deferred()
        dns_client_mock.lookupService.return_value = result_deferred

        cache = {}
        resolver = SrvResolver(dns_client=dns_client_mock, cache=cache)

        @defer.inlineCallbacks
        def do_lookup():

            with LoggingContext("one") as ctx:
                resolve_d = resolver.resolve_service(service_name)

                self.assertNoResult(resolve_d)

                # should have reset to the sentinel context
                self.assertIs(LoggingContext.current_context(), LoggingContext.sentinel)

                result = yield resolve_d

                # should have restored our context
                self.assertIs(LoggingContext.current_context(), ctx)

                defer.returnValue(result)

        test_d = do_lookup()
        self.assertNoResult(test_d)

        dns_client_mock.lookupService.assert_called_once_with(service_name)

        result_deferred.callback(([answer_srv], None, None))

        servers = self.successResultOf(test_d)

        self.assertEquals(len(servers), 1)
        self.assertEquals(servers, cache[service_name])
        self.assertEquals(servers[0].host, host_name)

    @defer.inlineCallbacks
    def test_from_cache_expired_and_dns_fail(self):
        dns_client_mock = Mock()
        dns_client_mock.lookupService.return_value = defer.fail(error.DNSServerError())

        service_name = b"test_service.example.com"

        entry = Mock(spec_set=["expires"])
        entry.expires = 0

        cache = {service_name: [entry]}
        resolver = SrvResolver(dns_client=dns_client_mock, cache=cache)

        servers = yield resolver.resolve_service(service_name)

        dns_client_mock.lookupService.assert_called_once_with(service_name)

        self.assertEquals(len(servers), 1)
        self.assertEquals(servers, cache[service_name])

    @defer.inlineCallbacks
    def test_from_cache(self):
        clock = MockClock()

        dns_client_mock = Mock(spec_set=["lookupService"])
        dns_client_mock.lookupService = Mock(spec_set=[])

        service_name = b"test_service.example.com"

        entry = Mock(spec_set=["expires"])
        entry.expires = 999999999

        cache = {service_name: [entry]}
        resolver = SrvResolver(
            dns_client=dns_client_mock, cache=cache, get_time=clock.time
        )

        servers = yield resolver.resolve_service(service_name)

        self.assertFalse(dns_client_mock.lookupService.called)

        self.assertEquals(len(servers), 1)
        self.assertEquals(servers, cache[service_name])

    @defer.inlineCallbacks
    def test_empty_cache(self):
        dns_client_mock = Mock()

        dns_client_mock.lookupService.return_value = defer.fail(error.DNSServerError())

        service_name = b"test_service.example.com"

        cache = {}
        resolver = SrvResolver(dns_client=dns_client_mock, cache=cache)

        with self.assertRaises(error.DNSServerError):
            yield resolver.resolve_service(service_name)

    @defer.inlineCallbacks
    def test_name_error(self):
        dns_client_mock = Mock()

        dns_client_mock.lookupService.return_value = defer.fail(error.DNSNameError())

        service_name = b"test_service.example.com"

        cache = {}
        resolver = SrvResolver(dns_client=dns_client_mock, cache=cache)

        servers = yield resolver.resolve_service(service_name)

        self.assertEquals(len(servers), 0)
        self.assertEquals(len(cache), 0)

    def test_disabled_service(self):
        """
        test the behaviour when there is a single record which is ".".
        """
        service_name = b"test_service.example.com"

        lookup_deferred = Deferred()
        dns_client_mock = Mock()
        dns_client_mock.lookupService.return_value = lookup_deferred
        cache = {}
        resolver = SrvResolver(dns_client=dns_client_mock, cache=cache)

        resolve_d = resolver.resolve_service(service_name)
        self.assertNoResult(resolve_d)

        # returning a single "." should make the lookup fail with a ConenctError
        lookup_deferred.callback(
            (
                [dns.RRHeader(type=dns.SRV, payload=dns.Record_SRV(target=b"."))],
                None,
                None,
            )
        )

        self.failureResultOf(resolve_d, ConnectError)

    def test_non_srv_answer(self):
        """
        test the behaviour when the dns server gives us a spurious non-SRV response
        """
        service_name = b"test_service.example.com"

        lookup_deferred = Deferred()
        dns_client_mock = Mock()
        dns_client_mock.lookupService.return_value = lookup_deferred
        cache = {}
        resolver = SrvResolver(dns_client=dns_client_mock, cache=cache)

        resolve_d = resolver.resolve_service(service_name)
        self.assertNoResult(resolve_d)

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

        self.assertEquals(len(servers), 1)
        self.assertEquals(servers, cache[service_name])
        self.assertEquals(servers[0].host, b"host")
