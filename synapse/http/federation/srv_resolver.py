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

import collections
import logging
import time

from twisted.internet import defer
from twisted.internet.error import ConnectError
from twisted.names import client, dns
from twisted.names.error import DNSNameError, DomainError

logger = logging.getLogger(__name__)

SERVER_CACHE = {}

_Server = collections.namedtuple(
    "_Server", "priority weight host port expires"
)


@defer.inlineCallbacks
def resolve_service(service_name, dns_client=client, cache=SERVER_CACHE, clock=time):
    """Look up a SRV record, with caching

    The default resolver in twisted.names doesn't do any caching (it has a CacheResolver,
    but the cache never gets populated), so we add our own caching layer here.

    Args:
        service_name (unicode|bytes): record to look up
        dns_client (twisted.internet.interfaces.IResolver): twisted resolver impl
        cache (dict): cache object
        clock (object): clock implementation. must provide a time() method.

    Returns:
        Deferred[list[_Server]]: a list of the SRV records, or an empty list if none found
    """
    # TODO: the dns client handles both unicode names (encoding via idna) and pre-encoded
    # byteses; however they will obviously end up as separate entries in the cache. We
    # should pick one form and stick with it.
    cache_entry = cache.get(service_name, None)
    if cache_entry:
        if all(s.expires > int(clock.time()) for s in cache_entry):
            servers = list(cache_entry)
            defer.returnValue(servers)

    servers = []

    try:
        try:
            answers, _, _ = yield dns_client.lookupService(service_name)
        except DNSNameError:
            # TODO: cache this. We can get the SOA out of the exception, and use
            # the negative-TTL value.
            defer.returnValue([])

        if (len(answers) == 1
                and answers[0].type == dns.SRV
                and answers[0].payload
                and answers[0].payload.target == dns.Name(b'.')):
            raise ConnectError("Service %s unavailable" % service_name)

        for answer in answers:
            if answer.type != dns.SRV or not answer.payload:
                continue

            payload = answer.payload

            servers.append(_Server(
                host=str(payload.target),
                port=int(payload.port),
                priority=int(payload.priority),
                weight=int(payload.weight),
                expires=int(clock.time()) + answer.ttl,
            ))

        servers.sort()
        cache[service_name] = list(servers)
    except DomainError as e:
        # We failed to resolve the name (other than a NameError)
        # Try something in the cache, else rereaise
        cache_entry = cache.get(service_name, None)
        if cache_entry:
            logger.warn(
                "Failed to resolve %r, falling back to cache. %r",
                service_name, e
            )
            servers = list(cache_entry)
        else:
            raise e

    defer.returnValue(servers)
