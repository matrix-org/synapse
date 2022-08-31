#  Copyright 2021 The Matrix.org Foundation C.I.C.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import functools
import logging
import re
import time
from http import HTTPStatus
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Dict, Optional, Tuple, cast

from synapse.api.errors import Codes, FederationDeniedError, SynapseError
from synapse.api.urls import FEDERATION_V1_PREFIX
from synapse.http.server import HttpServer, ServletCallback
from synapse.http.servlet import parse_json_object_from_request
from synapse.http.site import SynapseRequest
from synapse.logging.context import run_in_background
from synapse.logging.opentracing import (
    active_span,
    set_tag,
    span_context_from_request,
    start_active_span,
    start_active_span_follows_from,
    whitelisted_homeserver,
)
from synapse.types import JsonDict
from synapse.util.cancellation import is_function_cancellable
from synapse.util.ratelimitutils import FederationRateLimiter
from synapse.util.stringutils import parse_and_validate_server_name

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class AuthenticationError(SynapseError):
    """There was a problem authenticating the request"""


class NoAuthenticationError(AuthenticationError):
    """The request had no authentication information"""


class Authenticator:
    def __init__(self, hs: "HomeServer"):
        self._clock = hs.get_clock()
        self.keyring = hs.get_keyring()
        self.server_name = hs.hostname
        self.store = hs.get_datastores().main
        self.federation_domain_whitelist = (
            hs.config.federation.federation_domain_whitelist
        )
        self.notifier = hs.get_notifier()

        self.replication_client = None
        if hs.config.worker.worker_app:
            self.replication_client = hs.get_replication_command_handler()

    # A method just so we can pass 'self' as the authenticator to the Servlets
    async def authenticate_request(
        self, request: SynapseRequest, content: Optional[JsonDict]
    ) -> str:
        now = self._clock.time_msec()
        json_request: JsonDict = {
            "method": request.method.decode("ascii"),
            "uri": request.uri.decode("ascii"),
            "destination": self.server_name,
            "signatures": {},
        }

        if content is not None:
            json_request["content"] = content

        origin = None

        auth_headers = request.requestHeaders.getRawHeaders(b"Authorization")

        if not auth_headers:
            raise NoAuthenticationError(
                HTTPStatus.UNAUTHORIZED,
                "Missing Authorization headers",
                Codes.UNAUTHORIZED,
            )

        for auth in auth_headers:
            if auth.startswith(b"X-Matrix"):
                (origin, key, sig, destination) = _parse_auth_header(auth)
                json_request["origin"] = origin
                json_request["signatures"].setdefault(origin, {})[key] = sig

                # if the origin_server sent a destination along it needs to match our own server_name
                if destination is not None and destination != self.server_name:
                    raise AuthenticationError(
                        HTTPStatus.UNAUTHORIZED,
                        "Destination mismatch in auth header",
                        Codes.UNAUTHORIZED,
                    )
        if (
            self.federation_domain_whitelist is not None
            and origin not in self.federation_domain_whitelist
        ):
            raise FederationDeniedError(origin)

        if origin is None or not json_request["signatures"]:
            raise NoAuthenticationError(
                HTTPStatus.UNAUTHORIZED,
                "Missing Authorization headers",
                Codes.UNAUTHORIZED,
            )

        await self.keyring.verify_json_for_server(
            origin,
            json_request,
            now,
        )

        logger.debug("Request from %s", origin)
        request.requester = origin

        # If we get a valid signed request from the other side, its probably
        # alive
        retry_timings = await self.store.get_destination_retry_timings(origin)
        if retry_timings and retry_timings.retry_last_ts:
            run_in_background(self.reset_retry_timings, origin)

        return origin

    async def reset_retry_timings(self, origin: str) -> None:
        try:
            logger.info("Marking origin %r as up", origin)
            await self.store.set_destination_retry_timings(origin, None, 0, 0)

            # Inform the relevant places that the remote server is back up.
            self.notifier.notify_remote_server_up(origin)
            if self.replication_client:
                # If we're on a worker we try and inform master about this. The
                # replication client doesn't hook into the notifier to avoid
                # infinite loops where we send a `REMOTE_SERVER_UP` command to
                # master, which then echoes it back to us which in turn pokes
                # the notifier.
                self.replication_client.send_remote_server_up(origin)

        except Exception:
            logger.exception("Error resetting retry timings on %s", origin)


def _parse_auth_header(header_bytes: bytes) -> Tuple[str, str, str, Optional[str]]:
    """Parse an X-Matrix auth header

    Args:
        header_bytes: header value

    Returns:
        origin, key id, signature, destination.
        origin, key id, signature.

    Raises:
        AuthenticationError if the header could not be parsed
    """
    try:
        header_str = header_bytes.decode("utf-8")
        params = re.split(" +", header_str)[1].split(",")
        param_dict: Dict[str, str] = {
            k.lower(): v for k, v in [param.split("=", maxsplit=1) for param in params]
        }

        def strip_quotes(value: str) -> str:
            if value.startswith('"'):
                return re.sub(
                    "\\\\(.)", lambda matchobj: matchobj.group(1), value[1:-1]
                )
            else:
                return value

        origin = strip_quotes(param_dict["origin"])

        # ensure that the origin is a valid server name
        parse_and_validate_server_name(origin)

        key = strip_quotes(param_dict["key"])
        sig = strip_quotes(param_dict["sig"])

        # get the destination server_name from the auth header if it exists
        destination = param_dict.get("destination")
        if destination is not None:
            destination = strip_quotes(destination)
        else:
            destination = None

        return origin, key, sig, destination
    except Exception as e:
        logger.warning(
            "Error parsing auth header '%s': %s",
            header_bytes.decode("ascii", "replace"),
            e,
        )
        raise AuthenticationError(
            HTTPStatus.BAD_REQUEST, "Malformed Authorization header", Codes.UNAUTHORIZED
        )


class BaseFederationServlet:
    """Abstract base class for federation servlet classes.

    The servlet object should have a PATH attribute which takes the form of a regexp to
    match against the request path (excluding the /federation/v1 prefix).

    The servlet should also implement one or more of on_GET, on_POST, on_PUT, to match
    the appropriate HTTP method. These methods must be *asynchronous* and have the
    signature:

        on_<METHOD>(self, origin, content, query, **kwargs)

        With arguments:

            origin (unicode|None): The authenticated server_name of the calling server,
                unless REQUIRE_AUTH is set to False and authentication failed.

            content (unicode|None): decoded json body of the request. None if the
                request was a GET.

            query (dict[bytes, list[bytes]]): Query params from the request. url-decoded
                (ie, '+' and '%xx' are decoded) but note that it is *not* utf8-decoded
                yet.

            **kwargs (dict[unicode, unicode]): the dict mapping keys to path
                components as specified in the path match regexp.

        Returns:
            Optional[Tuple[int, object]]: either (response code, response object) to
                 return a JSON response, or None if the request has already been handled.

        Raises:
            SynapseError: to return an error code

            Exception: other exceptions will be caught, logged, and a 500 will be
                returned.
    """

    PATH = ""  # Overridden in subclasses, the regex to match against the path.

    REQUIRE_AUTH = True

    PREFIX = FEDERATION_V1_PREFIX  # Allows specifying the API version

    RATELIMIT = True  # Whether to rate limit requests or not

    def __init__(
        self,
        hs: "HomeServer",
        authenticator: Authenticator,
        ratelimiter: FederationRateLimiter,
        server_name: str,
    ):
        self.hs = hs
        self.authenticator = authenticator
        self.ratelimiter = ratelimiter
        self.server_name = server_name

    def _wrap(self, func: Callable[..., Awaitable[Tuple[int, Any]]]) -> ServletCallback:
        authenticator = self.authenticator
        ratelimiter = self.ratelimiter

        @functools.wraps(func)
        async def new_func(
            request: SynapseRequest, *args: Any, **kwargs: str
        ) -> Optional[Tuple[int, Any]]:
            """A callback which can be passed to HttpServer.RegisterPaths

            Args:
                request:
                *args: unused?
                **kwargs: the dict mapping keys to path components as specified
                    in the path match regexp.

            Returns:
                (response code, response object) as returned by the callback method.
                None if the request has already been handled.
            """
            content = None
            if request.method in [b"PUT", b"POST"]:
                # TODO: Handle other method types? other content types?
                content = parse_json_object_from_request(request)

            try:
                with start_active_span("authenticate_request"):
                    origin: Optional[str] = await authenticator.authenticate_request(
                        request, content
                    )
            except NoAuthenticationError:
                origin = None
                if self.REQUIRE_AUTH:
                    logger.warning(
                        "authenticate_request failed: missing authentication"
                    )
                    raise
            except Exception as e:
                logger.warning("authenticate_request failed: %s", e)
                raise

            # update the active opentracing span with the authenticated entity
            set_tag("authenticated_entity", str(origin))

            # if the origin is authenticated and whitelisted, use its span context
            # as the parent.
            context = None
            if origin and whitelisted_homeserver(origin):
                context = span_context_from_request(request)

            if context:
                servlet_span = active_span()
                # a scope which uses the origin's context as a parent
                processing_start_time = time.time()
                scope = start_active_span_follows_from(
                    "incoming-federation-request",
                    child_of=context,
                    contexts=(servlet_span,),
                    start_time=processing_start_time,
                )

            else:
                # just use our context as a parent
                scope = start_active_span(
                    "incoming-federation-request",
                )

            try:
                with scope:
                    if origin and self.RATELIMIT:
                        with ratelimiter.ratelimit(origin) as d:
                            await d
                            if request._disconnected:
                                logger.warning(
                                    "client disconnected before we started processing "
                                    "request"
                                )
                                return None
                            response = await func(
                                origin, content, request.args, *args, **kwargs
                            )
                    else:
                        response = await func(
                            origin, content, request.args, *args, **kwargs
                        )
            finally:
                # if we used the origin's context as the parent, add a new span using
                # the servlet span as a parent, so that we have a link
                if context:
                    scope2 = start_active_span_follows_from(
                        "process-federation_request",
                        contexts=(scope.span,),
                        start_time=processing_start_time,
                    )
                    scope2.close()

            return response

        return cast(ServletCallback, new_func)

    def register(self, server: HttpServer) -> None:
        pattern = re.compile("^" + self.PREFIX + self.PATH + "$")

        for method in ("GET", "PUT", "POST"):
            code = getattr(self, "on_%s" % (method), None)
            if code is None:
                continue

            if is_function_cancellable(code):
                # The wrapper added by `self._wrap` will inherit the cancellable flag,
                # but the wrapper itself does not support cancellation yet.
                # Once resolved, the cancellation tests in
                # `tests/federation/transport/server/test__base.py` can be re-enabled.
                raise Exception(
                    f"{self.__class__.__name__}.on_{method} has been marked as "
                    "cancellable, but federation servlets do not support cancellation "
                    "yet."
                )

            server.register_paths(
                method,
                (pattern,),
                self._wrap(code),
                self.__class__.__name__,
            )
