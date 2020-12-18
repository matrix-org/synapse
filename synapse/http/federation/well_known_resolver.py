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
import logging
import random
import time
from io import BytesIO
from typing import Callable, Dict, Optional, Tuple

import attr

from twisted.internet import defer
from twisted.internet.interfaces import IReactorTime
from twisted.web.client import RedirectAgent
from twisted.web.http import stringToDatetime
from twisted.web.http_headers import Headers
from twisted.web.iweb import IAgent, IResponse

from synapse.http.client import BodyExceededMaxSize, read_body_with_max_size
from synapse.logging.context import make_deferred_yieldable
from synapse.util import Clock, json_decoder
from synapse.util.caches.ttlcache import TTLCache
from synapse.util.metrics import Measure

# period to cache .well-known results for by default
WELL_KNOWN_DEFAULT_CACHE_PERIOD = 24 * 3600

# jitter factor to add to the .well-known default cache ttls
WELL_KNOWN_DEFAULT_CACHE_PERIOD_JITTER = 0.1

# period to cache failure to fetch .well-known for
WELL_KNOWN_INVALID_CACHE_PERIOD = 1 * 3600

# period to cache failure to fetch .well-known if there has recently been a
# valid well-known for that domain.
WELL_KNOWN_DOWN_CACHE_PERIOD = 2 * 60

# period to remember there was a valid well-known after valid record expires
WELL_KNOWN_REMEMBER_DOMAIN_HAD_VALID = 2 * 3600

# cap for .well-known cache period
WELL_KNOWN_MAX_CACHE_PERIOD = 48 * 3600

# lower bound for .well-known cache period
WELL_KNOWN_MIN_CACHE_PERIOD = 5 * 60

# The maximum size (in bytes) to allow a well-known file to be.
WELL_KNOWN_MAX_SIZE = 50 * 1024  # 50 KiB

# Attempt to refetch a cached well-known N% of the TTL before it expires.
# e.g. if set to 0.2 and we have a cached entry with a TTL of 5mins, then
# we'll start trying to refetch 1 minute before it expires.
WELL_KNOWN_GRACE_PERIOD_FACTOR = 0.2

# Number of times we retry fetching a well-known for a domain we know recently
# had a valid entry.
WELL_KNOWN_RETRY_ATTEMPTS = 3


logger = logging.getLogger(__name__)


_well_known_cache = TTLCache("well-known")
_had_valid_well_known_cache = TTLCache("had-valid-well-known")


@attr.s(slots=True, frozen=True)
class WellKnownLookupResult:
    delegated_server = attr.ib()


class WellKnownResolver:
    """Handles well-known lookups for matrix servers.
    """

    def __init__(
        self,
        reactor: IReactorTime,
        agent: IAgent,
        user_agent: bytes,
        well_known_cache: Optional[TTLCache] = None,
        had_well_known_cache: Optional[TTLCache] = None,
    ):
        self._reactor = reactor
        self._clock = Clock(reactor)

        if well_known_cache is None:
            well_known_cache = _well_known_cache

        if had_well_known_cache is None:
            had_well_known_cache = _had_valid_well_known_cache

        self._well_known_cache = well_known_cache
        self._had_valid_well_known_cache = had_well_known_cache
        self._well_known_agent = RedirectAgent(agent)
        self.user_agent = user_agent

    async def get_well_known(self, server_name: bytes) -> WellKnownLookupResult:
        """Attempt to fetch and parse a .well-known file for the given server

        Args:
            server_name: name of the server, from the requested url

        Returns:
            The result of the lookup
        """
        try:
            prev_result, expiry, ttl = self._well_known_cache.get_with_expiry(
                server_name
            )

            now = self._clock.time()
            if now < expiry - WELL_KNOWN_GRACE_PERIOD_FACTOR * ttl:
                return WellKnownLookupResult(delegated_server=prev_result)
        except KeyError:
            prev_result = None

        # TODO: should we linearise so that we don't end up doing two .well-known
        # requests for the same server in parallel?
        try:
            with Measure(self._clock, "get_well_known"):
                result, cache_period = await self._fetch_well_known(
                    server_name
                )  # type: Optional[bytes], float

        except _FetchWellKnownFailure as e:
            if prev_result and e.temporary:
                # This is a temporary failure and we have a still valid cached
                # result, so lets return that. Hopefully the next time we ask
                # the remote will be back up again.
                return WellKnownLookupResult(delegated_server=prev_result)

            result = None

            if self._had_valid_well_known_cache.get(server_name, False):
                # We have recently seen a valid well-known record for this
                # server, so we cache the lack of well-known for a shorter time.
                cache_period = WELL_KNOWN_DOWN_CACHE_PERIOD
            else:
                cache_period = WELL_KNOWN_INVALID_CACHE_PERIOD

            # add some randomness to the TTL to avoid a stampeding herd
            cache_period *= random.uniform(
                1 - WELL_KNOWN_DEFAULT_CACHE_PERIOD_JITTER,
                1 + WELL_KNOWN_DEFAULT_CACHE_PERIOD_JITTER,
            )

        if cache_period > 0:
            self._well_known_cache.set(server_name, result, cache_period)

        return WellKnownLookupResult(delegated_server=result)

    async def _fetch_well_known(self, server_name: bytes) -> Tuple[bytes, float]:
        """Actually fetch and parse a .well-known, without checking the cache

        Args:
            server_name: name of the server, from the requested url

        Raises:
            _FetchWellKnownFailure if we fail to lookup a result

        Returns:
            The lookup result and cache period.
        """

        had_valid_well_known = self._had_valid_well_known_cache.get(server_name, False)

        # We do this in two steps to differentiate between possibly transient
        # errors (e.g. can't connect to host, 503 response) and more permanent
        # errors (such as getting a 404 response).
        response, body = await self._make_well_known_request(
            server_name, retry=had_valid_well_known
        )

        try:
            if response.code != 200:
                raise Exception("Non-200 response %s" % (response.code,))

            parsed_body = json_decoder.decode(body.decode("utf-8"))
            logger.info("Response from .well-known: %s", parsed_body)

            result = parsed_body["m.server"].encode("ascii")
        except defer.CancelledError:
            # Bail if we've been cancelled
            raise
        except Exception as e:
            logger.info("Error parsing well-known for %s: %s", server_name, e)
            raise _FetchWellKnownFailure(temporary=False)

        cache_period = _cache_period_from_headers(
            response.headers, time_now=self._reactor.seconds
        )
        if cache_period is None:
            cache_period = WELL_KNOWN_DEFAULT_CACHE_PERIOD
            # add some randomness to the TTL to avoid a stampeding herd every 24 hours
            # after startup
            cache_period *= random.uniform(
                1 - WELL_KNOWN_DEFAULT_CACHE_PERIOD_JITTER,
                1 + WELL_KNOWN_DEFAULT_CACHE_PERIOD_JITTER,
            )
        else:
            cache_period = min(cache_period, WELL_KNOWN_MAX_CACHE_PERIOD)
            cache_period = max(cache_period, WELL_KNOWN_MIN_CACHE_PERIOD)

        # We got a success, mark as such in the cache
        self._had_valid_well_known_cache.set(
            server_name,
            bool(result),
            cache_period + WELL_KNOWN_REMEMBER_DOMAIN_HAD_VALID,
        )

        return result, cache_period

    async def _make_well_known_request(
        self, server_name: bytes, retry: bool
    ) -> Tuple[IResponse, bytes]:
        """Make the well known request.

        This will retry the request if requested and it fails (with unable
        to connect or receives a 5xx error).

        Args:
            server_name: name of the server, from the requested url
            retry: Whether to retry the request if it fails.

        Raises:
            _FetchWellKnownFailure if we fail to lookup a result

        Returns:
            Returns the response object and body. Response may be a non-200 response.
        """
        uri = b"https://%s/.well-known/matrix/server" % (server_name,)
        uri_str = uri.decode("ascii")

        headers = {
            b"User-Agent": [self.user_agent],
        }

        i = 0
        while True:
            i += 1

            logger.info("Fetching %s", uri_str)
            try:
                response = await make_deferred_yieldable(
                    self._well_known_agent.request(
                        b"GET", uri, headers=Headers(headers)
                    )
                )
                body_stream = BytesIO()
                await make_deferred_yieldable(
                    read_body_with_max_size(response, body_stream, WELL_KNOWN_MAX_SIZE)
                )
                body = body_stream.getvalue()

                if 500 <= response.code < 600:
                    raise Exception("Non-200 response %s" % (response.code,))

                return response, body
            except defer.CancelledError:
                # Bail if we've been cancelled
                raise
            except BodyExceededMaxSize:
                # If the well-known file was too large, do not keep attempting
                # to download it, but consider it a temporary error.
                logger.warning(
                    "Requested .well-known file for %s is too large > %r bytes",
                    server_name.decode("ascii"),
                    WELL_KNOWN_MAX_SIZE,
                )
                raise _FetchWellKnownFailure(temporary=True)
            except Exception as e:
                if not retry or i >= WELL_KNOWN_RETRY_ATTEMPTS:
                    logger.info("Error fetching %s: %s", uri_str, e)
                    raise _FetchWellKnownFailure(temporary=True)

                logger.info("Error fetching %s: %s. Retrying", uri_str, e)

            # Sleep briefly in the hopes that they come back up
            await self._clock.sleep(0.5)


def _cache_period_from_headers(
    headers: Headers, time_now: Callable[[], float] = time.time
) -> Optional[float]:
    cache_controls = _parse_cache_control(headers)

    if b"no-store" in cache_controls:
        return 0

    if b"max-age" in cache_controls:
        max_age = cache_controls[b"max-age"]
        if max_age:
            try:
                return int(max_age)
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


def _parse_cache_control(headers: Headers) -> Dict[bytes, Optional[bytes]]:
    cache_controls = {}
    for hdr in headers.getRawHeaders(b"cache-control", []):
        for directive in hdr.split(b","):
            splits = [x.strip() for x in directive.split(b"=", 1)]
            k = splits[0].lower()
            v = splits[1] if len(splits) > 1 else None
            cache_controls[k] = v
    return cache_controls


@attr.s(slots=True)
class _FetchWellKnownFailure(Exception):
    # True if we didn't get a non-5xx HTTP response, i.e. this may or may not be
    # a temporary failure.
    temporary = attr.ib()
