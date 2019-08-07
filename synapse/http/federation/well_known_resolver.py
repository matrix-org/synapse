# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.
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

import json
import logging
import random
import time

import attr

from twisted.internet import defer
from twisted.web.client import RedirectAgent, readBody
from twisted.web.http import stringToDatetime

from synapse.logging.context import make_deferred_yieldable
from synapse.util import Clock
from synapse.util.caches.ttlcache import TTLCache
from synapse.util.metrics import Measure

# period to cache .well-known results for by default
WELL_KNOWN_DEFAULT_CACHE_PERIOD = 24 * 3600

# jitter to add to the .well-known default cache ttl
WELL_KNOWN_DEFAULT_CACHE_PERIOD_JITTER = 10 * 60

# period to cache failure to fetch .well-known for
WELL_KNOWN_INVALID_CACHE_PERIOD = 1 * 3600

# cap for .well-known cache period
WELL_KNOWN_MAX_CACHE_PERIOD = 48 * 3600

# lower bound for .well-known cache period
WELL_KNOWN_MIN_CACHE_PERIOD = 5 * 60

logger = logging.getLogger(__name__)


@attr.s(slots=True, frozen=True)
class WellKnownLookupResult(object):
    delegated_server = attr.ib()


class WellKnownResolver(object):
    """Handles well-known lookups for matrix servers.
    """

    def __init__(self, reactor, agent, well_known_cache=None):
        self._reactor = reactor
        self._clock = Clock(reactor)

        if well_known_cache is None:
            well_known_cache = TTLCache("well-known")

        self._well_known_cache = well_known_cache
        self._well_known_agent = RedirectAgent(agent)

    @defer.inlineCallbacks
    def get_well_known(self, server_name):
        """Attempt to fetch and parse a .well-known file for the given server

        Args:
            server_name (bytes): name of the server, from the requested url

        Returns:
            Deferred[WellKnownLookupResult]: The result of the lookup
        """
        try:
            result = self._well_known_cache[server_name]
        except KeyError:
            # TODO: should we linearise so that we don't end up doing two .well-known
            # requests for the same server in parallel?
            with Measure(self._clock, "get_well_known"):
                result, cache_period = yield self._do_get_well_known(server_name)

            if cache_period > 0:
                self._well_known_cache.set(server_name, result, cache_period)

        return WellKnownLookupResult(delegated_server=result)

    @defer.inlineCallbacks
    def _do_get_well_known(self, server_name):
        """Actually fetch and parse a .well-known, without checking the cache

        Args:
            server_name (bytes): name of the server, from the requested url

        Returns:
            Deferred[Tuple[bytes|None|object],int]:
                result, cache period, where result is one of:
                 - the new server name from the .well-known (as a `bytes`)
                 - None if there was no .well-known file.
                 - INVALID_WELL_KNOWN if the .well-known was invalid
        """
        uri = b"https://%s/.well-known/matrix/server" % (server_name,)
        uri_str = uri.decode("ascii")
        logger.info("Fetching %s", uri_str)
        try:
            response = yield make_deferred_yieldable(
                self._well_known_agent.request(b"GET", uri)
            )
            body = yield make_deferred_yieldable(readBody(response))
            if response.code != 200:
                raise Exception("Non-200 response %s" % (response.code,))

            parsed_body = json.loads(body.decode("utf-8"))
            logger.info("Response from .well-known: %s", parsed_body)
            if not isinstance(parsed_body, dict):
                raise Exception("not a dict")
            if "m.server" not in parsed_body:
                raise Exception("Missing key 'm.server'")
        except Exception as e:
            logger.info("Error fetching %s: %s", uri_str, e)

            # add some randomness to the TTL to avoid a stampeding herd every hour
            # after startup
            cache_period = WELL_KNOWN_INVALID_CACHE_PERIOD
            cache_period += random.uniform(0, WELL_KNOWN_DEFAULT_CACHE_PERIOD_JITTER)
            return (None, cache_period)

        result = parsed_body["m.server"].encode("ascii")

        cache_period = _cache_period_from_headers(
            response.headers, time_now=self._reactor.seconds
        )
        if cache_period is None:
            cache_period = WELL_KNOWN_DEFAULT_CACHE_PERIOD
            # add some randomness to the TTL to avoid a stampeding herd every 24 hours
            # after startup
            cache_period += random.uniform(0, WELL_KNOWN_DEFAULT_CACHE_PERIOD_JITTER)
        else:
            cache_period = min(cache_period, WELL_KNOWN_MAX_CACHE_PERIOD)
            cache_period = max(cache_period, WELL_KNOWN_MIN_CACHE_PERIOD)

        return (result, cache_period)


def _cache_period_from_headers(headers, time_now=time.time):
    cache_controls = _parse_cache_control(headers)

    if b"no-store" in cache_controls:
        return 0

    if b"max-age" in cache_controls:
        try:
            max_age = int(cache_controls[b"max-age"])
            return max_age
        except ValueError:
            pass

    expires = headers.getRawHeaders(b"expires")
    if expires is not None:
        try:
            expires_date = stringToDatetime(expires[-1])
            return expires_date - time_now()
        except ValueError:
            # RFC7234 says 'A cache recipient MUST interpret invalid date formats,
            # especially the value "0", as representing a time in the past (i.e.,
            # "already expired").
            return 0

    return None


def _parse_cache_control(headers):
    cache_controls = {}
    for hdr in headers.getRawHeaders(b"cache-control", []):
        for directive in hdr.split(b","):
            splits = [x.strip() for x in directive.split(b"=", 1)]
            k = splits[0].lower()
            v = splits[1] if len(splits) > 1 else None
            cache_controls[k] = v
    return cache_controls
