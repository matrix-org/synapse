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

import logging
import random
import time
from typing import List

import attr

from twisted.internet.error import ConnectError
from twisted.names import client, dns
from twisted.names.error import DNSNameError, DomainError

from synapse.logging.context import make_deferred_yieldable

logger = logging.getLogger(__name__)

SERVER_CACHE = {}


@attr.s(slots=True, frozen=True)
class Server:
    """
    Our record of an individual server which can be tried to reach a destination.

    Attributes:
        host (bytes): target hostname
        port (int):
        priority (int):
        weight (int):
        expires (int): when the cache should expire this record - in *seconds* since
            the epoch
    """

    host = attr.ib()
    port = attr.ib()
    priority = attr.ib(default=0)
    weight = attr.ib(default=0)
    expires = attr.ib(default=0)


def _sort_server_list(server_list):
    """Given a list of SRV records sort them into priority order and shuffle
    each priority with the given weight.
    """
    priority_map = {}

    for server in server_list:
        priority_map.setdefault(server.priority, []).append(server)

    results = []
    for priority in sorted(priority_map):
        servers = priority_map[priority]

        # This algorithms roughly follows the algorithm described in RFC2782,
        # changed to remove an off-by-one error.
        #
        # N.B. Weights can be zero, which means that they should be picked
        # rarely.

        total_weight = sum(s.weight for s in servers)

        # Total weight can become zero if there are only zero weight servers
        # left, which we handle by just shuffling and appending to the results.
        while servers and total_weight:
            target_weight = random.randint(1, total_weight)

            for s in servers:
                target_weight -= s.weight

                if target_weight <= 0:
                    break

            results.append(s)
            servers.remove(s)
            total_weight -= s.weight

        if servers:
            random.shuffle(servers)
            results.extend(servers)

    return results


class SrvResolver:
    """Interface to the dns client to do SRV lookups, with result caching.

    The default resolver in twisted.names doesn't do any caching (it has a CacheResolver,
    but the cache never gets populated), so we add our own caching layer here.

    Args:
        dns_client (twisted.internet.interfaces.IResolver): twisted resolver impl
        cache (dict): cache object
        get_time (callable): clock implementation. Should return seconds since the epoch
    """

    def __init__(self, dns_client=client, cache=SERVER_CACHE, get_time=time.time):
        self._dns_client = dns_client
        self._cache = cache
        self._get_time = get_time

    async def resolve_service(self, service_name: bytes) -> List[Server]:
        """Look up a SRV record

        Args:
            service_name (bytes): record to look up

        Returns:
            a list of the SRV records, or an empty list if none found
        """
        now = int(self._get_time())

        if not isinstance(service_name, bytes):
            raise TypeError("%r is not a byte string" % (service_name,))

        cache_entry = self._cache.get(service_name, None)
        if cache_entry:
            if all(s.expires > now for s in cache_entry):
                servers = list(cache_entry)
                return _sort_server_list(servers)

        try:
            answers, _, _ = await make_deferred_yieldable(
                self._dns_client.lookupService(service_name)
            )
        except DNSNameError:
            # TODO: cache this. We can get the SOA out of the exception, and use
            # the negative-TTL value.
            return []
        except DomainError as e:
            # We failed to resolve the name (other than a NameError)
            # Try something in the cache, else rereaise
            cache_entry = self._cache.get(service_name, None)
            if cache_entry:
                logger.warning(
                    "Failed to resolve %r, falling back to cache. %r", service_name, e
                )
                return list(cache_entry)
            else:
                raise e

        if (
            len(answers) == 1
            and answers[0].type == dns.SRV
            and answers[0].payload
            and answers[0].payload.target == dns.Name(b".")
        ):
            raise ConnectError("Service %s unavailable" % service_name)

        servers = []

        for answer in answers:
            if answer.type != dns.SRV or not answer.payload:
                continue

            payload = answer.payload

            servers.append(
                Server(
                    host=payload.target.name,
                    port=payload.port,
                    priority=payload.priority,
                    weight=payload.weight,
                    expires=now + answer.ttl,
                )
            )

        self._cache[service_name] = list(servers)
        return _sort_server_list(servers)
