# Copyright 2014-2021 The Matrix.org Foundation C.I.C.
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
import abc
import cgi
import codecs
import logging
import random
import sys
import typing
import urllib.parse
from http import HTTPStatus
from io import BytesIO, StringIO
from typing import (
    TYPE_CHECKING,
    Any,
    BinaryIO,
    Callable,
    Dict,
    Generic,
    List,
    Optional,
    Tuple,
    TypeVar,
    Union,
    overload,
)

import attr
import treq
from canonicaljson import encode_canonical_json
from prometheus_client import Counter
from signedjson.sign import sign_json
from typing_extensions import Literal

from twisted.internet import defer
from twisted.internet.error import DNSLookupError
from twisted.internet.interfaces import IReactorTime
from twisted.internet.task import Cooperator
from twisted.web.client import ResponseFailed
from twisted.web.http_headers import Headers
from twisted.web.iweb import IBodyProducer, IResponse

import synapse.metrics
import synapse.util.retryutils
from synapse.api.errors import (
    Codes,
    FederationDeniedError,
    HttpResponseException,
    RequestSendFailed,
    SynapseError,
)
from synapse.crypto.context_factory import FederationPolicyForHTTPS
from synapse.http import QuieterFileBodyProducer
from synapse.http.client import (
    BlacklistingAgentWrapper,
    BodyExceededMaxSize,
    ByteWriteable,
    _make_scheduler,
    encode_query_args,
    read_body_with_max_size,
)
from synapse.http.federation.matrix_federation_agent import MatrixFederationAgent
from synapse.http.types import QueryParams
from synapse.logging import opentracing
from synapse.logging.context import make_deferred_yieldable, run_in_background
from synapse.logging.opentracing import set_tag, start_active_span, tags
from synapse.types import JsonDict
from synapse.util import json_decoder
from synapse.util.async_helpers import AwakenableSleeper, timeout_deferred
from synapse.util.metrics import Measure

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

outgoing_requests_counter = Counter(
    "synapse_http_matrixfederationclient_requests", "", ["method"]
)
incoming_responses_counter = Counter(
    "synapse_http_matrixfederationclient_responses", "", ["method", "code"]
)


MAX_LONG_RETRIES = 10
MAX_SHORT_RETRIES = 3
MAXINT = sys.maxsize


_next_id = 1

T = TypeVar("T")


class ByteParser(ByteWriteable, Generic[T], abc.ABC):
    """A `ByteWriteable` that has an additional `finish` function that returns
    the parsed data.
    """

    CONTENT_TYPE: str = abc.abstractproperty()  # type: ignore
    """The expected content type of the response, e.g. `application/json`. If
    the content type doesn't match we fail the request.
    """

    # a federation response can be rather large (eg a big state_ids is 50M or so), so we
    # need a generous limit here.
    MAX_RESPONSE_SIZE: int = 100 * 1024 * 1024
    """The largest response this parser will accept."""

    @abc.abstractmethod
    def finish(self) -> T:
        """Called when response has finished streaming and the parser should
        return the final result (or error).
        """


@attr.s(slots=True, frozen=True, auto_attribs=True)
class MatrixFederationRequest:
    method: str
    """HTTP method
    """

    path: str
    """HTTP path
    """

    destination: str
    """The remote server to send the HTTP request to.
    """

    json: Optional[JsonDict] = None
    """JSON to send in the body.
    """

    json_callback: Optional[Callable[[], JsonDict]] = None
    """A callback to generate the JSON.
    """

    query: Optional[QueryParams] = None
    """Query arguments.
    """

    txn_id: Optional[str] = None
    """Unique ID for this request (for logging)
    """

    uri: bytes = attr.ib(init=False)
    """The URI of this request
    """

    def __attrs_post_init__(self) -> None:
        global _next_id
        txn_id = "%s-O-%s" % (self.method, _next_id)
        _next_id = (_next_id + 1) % (MAXINT - 1)

        object.__setattr__(self, "txn_id", txn_id)

        destination_bytes = self.destination.encode("ascii")
        path_bytes = self.path.encode("ascii")
        query_bytes = encode_query_args(self.query)

        # The object is frozen so we can pre-compute this.
        uri = urllib.parse.urlunparse(
            (b"matrix", destination_bytes, path_bytes, None, query_bytes, b"")
        )
        object.__setattr__(self, "uri", uri)

    def get_json(self) -> Optional[JsonDict]:
        if self.json_callback:
            return self.json_callback()
        return self.json


class JsonParser(ByteParser[Union[JsonDict, list]]):
    """A parser that buffers the response and tries to parse it as JSON."""

    CONTENT_TYPE = "application/json"

    def __init__(self) -> None:
        self._buffer = StringIO()
        self._binary_wrapper = BinaryIOWrapper(self._buffer)

    def write(self, data: bytes) -> int:
        return self._binary_wrapper.write(data)

    def finish(self) -> Union[JsonDict, list]:
        return json_decoder.decode(self._buffer.getvalue())


async def _handle_response(
    reactor: IReactorTime,
    timeout_sec: float,
    request: MatrixFederationRequest,
    response: IResponse,
    start_ms: int,
    parser: ByteParser[T],
) -> T:
    """
    Reads the body of a response with a timeout and sends it to a parser

    Args:
        reactor: twisted reactor, for the timeout
        timeout_sec: number of seconds to wait for response to complete
        request: the request that triggered the response
        response: response to the request
        start_ms: Timestamp when request was made
        parser: The parser for the response

    Returns:
        The parsed response
    """

    max_response_size = parser.MAX_RESPONSE_SIZE

    finished = False
    try:
        check_content_type_is(response.headers, parser.CONTENT_TYPE)

        d = read_body_with_max_size(response, parser, max_response_size)
        d = timeout_deferred(d, timeout=timeout_sec, reactor=reactor)

        length = await make_deferred_yieldable(d)

        finished = True
        value = parser.finish()
    except BodyExceededMaxSize as e:
        # The response was too big.
        logger.warning(
            "{%s} [%s] JSON response exceeded max size %i - %s %s",
            request.txn_id,
            request.destination,
            max_response_size,
            request.method,
            request.uri.decode("ascii"),
        )
        raise RequestSendFailed(e, can_retry=False) from e
    except ValueError as e:
        # The content was invalid.
        logger.warning(
            "{%s} [%s] Failed to parse response - %s %s",
            request.txn_id,
            request.destination,
            request.method,
            request.uri.decode("ascii"),
        )
        raise RequestSendFailed(e, can_retry=False) from e
    except defer.TimeoutError as e:
        logger.warning(
            "{%s} [%s] Timed out reading response - %s %s",
            request.txn_id,
            request.destination,
            request.method,
            request.uri.decode("ascii"),
        )
        raise RequestSendFailed(e, can_retry=True) from e
    except ResponseFailed as e:
        logger.warning(
            "{%s} [%s] Failed to read response - %s %s",
            request.txn_id,
            request.destination,
            request.method,
            request.uri.decode("ascii"),
        )
        raise RequestSendFailed(e, can_retry=True) from e
    except Exception as e:
        logger.warning(
            "{%s} [%s] Error reading response %s %s: %s",
            request.txn_id,
            request.destination,
            request.method,
            request.uri.decode("ascii"),
            e,
        )
        raise
    finally:
        if not finished:
            # There was an exception and we didn't `finish()` the parse.
            # Let the parser know that it can free up any resources.
            try:
                parser.finish()
            except Exception:
                # Ignore any additional exceptions.
                pass

    time_taken_secs = reactor.seconds() - start_ms / 1000

    logger.info(
        "{%s} [%s] Completed request: %d %s in %.2f secs, got %d bytes - %s %s",
        request.txn_id,
        request.destination,
        response.code,
        response.phrase.decode("ascii", errors="replace"),
        time_taken_secs,
        length,
        request.method,
        request.uri.decode("ascii"),
    )
    return value


class BinaryIOWrapper:
    """A wrapper for a TextIO which converts from bytes on the fly."""

    def __init__(
        self, file: typing.TextIO, encoding: str = "utf-8", errors: str = "strict"
    ):
        self.decoder = codecs.getincrementaldecoder(encoding)(errors)
        self.file = file

    def write(self, b: Union[bytes, bytearray]) -> int:
        self.file.write(self.decoder.decode(b))
        return len(b)


class MatrixFederationHttpClient:
    """HTTP client used to talk to other homeservers over the federation
    protocol. Send client certificates and signs requests.

    Attributes:
        agent (twisted.web.client.Agent): The twisted Agent used to send the
            requests.
    """

    def __init__(
        self,
        hs: "HomeServer",
        tls_client_options_factory: Optional[FederationPolicyForHTTPS],
    ):
        self.hs = hs
        self.signing_key = hs.signing_key
        self.server_name = hs.hostname

        self.reactor = hs.get_reactor()

        user_agent = hs.version_string
        if hs.config.server.user_agent_suffix:
            user_agent = "%s %s" % (user_agent, hs.config.server.user_agent_suffix)

        federation_agent = MatrixFederationAgent(
            self.reactor,
            tls_client_options_factory,
            user_agent.encode("ascii"),
            hs.config.server.federation_ip_range_whitelist,
            hs.config.server.federation_ip_range_blacklist,
        )

        # Use a BlacklistingAgentWrapper to prevent circumventing the IP
        # blacklist via IP literals in server names
        self.agent = BlacklistingAgentWrapper(
            federation_agent,
            ip_blacklist=hs.config.server.federation_ip_range_blacklist,
        )

        self.clock = hs.get_clock()
        self._store = hs.get_datastores().main
        self.version_string_bytes = hs.version_string.encode("ascii")
        self.default_timeout = 60

        self._cooperator = Cooperator(scheduler=_make_scheduler(self.reactor))

        self._sleeper = AwakenableSleeper(self.reactor)

    def wake_destination(self, destination: str) -> None:
        """Called when the remote server may have come back online."""

        self._sleeper.wake(destination)

    async def _send_request_with_optional_trailing_slash(
        self,
        request: MatrixFederationRequest,
        try_trailing_slash_on_400: bool = False,
        **send_request_args: Any,
    ) -> IResponse:
        """Wrapper for _send_request which can optionally retry the request
        upon receiving a combination of a 400 HTTP response code and a
        'M_UNRECOGNIZED' errcode. This is a workaround for Synapse <= v0.99.3
        due to #3622.

        Args:
            request: details of request to be sent
            try_trailing_slash_on_400: Whether on receiving a 400
                'M_UNRECOGNIZED' from the server to retry the request with a
                trailing slash appended to the request path.
            send_request_args: A dictionary of arguments to pass to `_send_request()`.

        Raises:
            HttpResponseException: If we get an HTTP response code >= 300
                (except 429).

        Returns:
            Parsed JSON response body.
        """
        try:
            response = await self._send_request(request, **send_request_args)
        except HttpResponseException as e:
            # Received an HTTP error > 300. Check if it meets the requirements
            # to retry with a trailing slash
            if not try_trailing_slash_on_400:
                raise

            if e.code != 400 or e.to_synapse_error().errcode != "M_UNRECOGNIZED":
                raise

            # Retry with a trailing slash if we received a 400 with
            # 'M_UNRECOGNIZED' which some endpoints can return when omitting a
            # trailing slash on Synapse <= v0.99.3.
            logger.info("Retrying request with trailing slash")

            # Request is frozen so we create a new instance
            request = attr.evolve(request, path=request.path + "/")

            response = await self._send_request(request, **send_request_args)

        return response

    async def _send_request(
        self,
        request: MatrixFederationRequest,
        retry_on_dns_fail: bool = True,
        timeout: Optional[int] = None,
        long_retries: bool = False,
        ignore_backoff: bool = False,
        backoff_on_404: bool = False,
    ) -> IResponse:
        """
        Sends a request to the given server.

        Args:
            request: details of request to be sent

            retry_on_dns_fail: true if the request should be retied on DNS failures

            timeout: number of milliseconds to wait for the response headers
                (including connecting to the server), *for each attempt*.
                60s by default.

            long_retries: whether to use the long retry algorithm.

                The regular retry algorithm makes 4 attempts, with intervals
                [0.5s, 1s, 2s].

                The long retry algorithm makes 11 attempts, with intervals
                [4s, 16s, 60s, 60s, ...]

                Both algorithms add -20%/+40% jitter to the retry intervals.

                Note that the above intervals are *in addition* to the time spent
                waiting for the request to complete (up to `timeout` ms).

                NB: the long retry algorithm takes over 20 minutes to complete, with
                a default timeout of 60s!

            ignore_backoff: true to ignore the historical backoff data
                and try the request anyway.

            backoff_on_404: Back off if we get a 404

        Returns:
            Resolves with the HTTP response object on success.

        Raises:
            HttpResponseException: If we get an HTTP response code >= 300
                (except 429).
            NotRetryingDestination: If we are not yet ready to retry this
                server.
            FederationDeniedError: If this destination  is not on our
                federation whitelist
            RequestSendFailed: If there were problems connecting to the
                remote, due to e.g. DNS failures, connection timeouts etc.
        """
        if timeout:
            _sec_timeout = timeout / 1000
        else:
            _sec_timeout = self.default_timeout

        if (
            self.hs.config.federation.federation_domain_whitelist is not None
            and request.destination
            not in self.hs.config.federation.federation_domain_whitelist
        ):
            raise FederationDeniedError(request.destination)

        limiter = await synapse.util.retryutils.get_retry_limiter(
            request.destination,
            self.clock,
            self._store,
            backoff_on_404=backoff_on_404,
            ignore_backoff=ignore_backoff,
            notifier=self.hs.get_notifier(),
            replication_client=self.hs.get_replication_command_handler(),
        )

        method_bytes = request.method.encode("ascii")
        destination_bytes = request.destination.encode("ascii")
        path_bytes = request.path.encode("ascii")
        query_bytes = encode_query_args(request.query)

        scope = start_active_span(
            "outgoing-federation-request",
            tags={
                tags.SPAN_KIND: tags.SPAN_KIND_RPC_CLIENT,
                tags.PEER_ADDRESS: request.destination,
                tags.HTTP_METHOD: request.method,
                tags.HTTP_URL: request.path,
            },
            finish_on_close=True,
        )

        # Inject the span into the headers
        headers_dict: Dict[bytes, List[bytes]] = {}
        opentracing.inject_header_dict(headers_dict, request.destination)

        headers_dict[b"User-Agent"] = [self.version_string_bytes]

        with limiter, scope:
            # XXX: Would be much nicer to retry only at the transaction-layer
            # (once we have reliable transactions in place)
            if long_retries:
                retries_left = MAX_LONG_RETRIES
            else:
                retries_left = MAX_SHORT_RETRIES

            url_bytes = request.uri
            url_str = url_bytes.decode("ascii")

            url_to_sign_bytes = urllib.parse.urlunparse(
                (b"", b"", path_bytes, None, query_bytes, b"")
            )

            while True:
                try:
                    json = request.get_json()
                    if json:
                        headers_dict[b"Content-Type"] = [b"application/json"]
                        auth_headers = self.build_auth_headers(
                            destination_bytes, method_bytes, url_to_sign_bytes, json
                        )
                        data = encode_canonical_json(json)
                        producer: Optional[IBodyProducer] = QuieterFileBodyProducer(
                            BytesIO(data), cooperator=self._cooperator
                        )
                    else:
                        producer = None
                        auth_headers = self.build_auth_headers(
                            destination_bytes, method_bytes, url_to_sign_bytes
                        )

                    headers_dict[b"Authorization"] = auth_headers

                    logger.debug(
                        "{%s} [%s] Sending request: %s %s; timeout %fs",
                        request.txn_id,
                        request.destination,
                        request.method,
                        url_str,
                        _sec_timeout,
                    )

                    outgoing_requests_counter.labels(request.method).inc()

                    try:
                        with Measure(self.clock, "outbound_request"):
                            # we don't want all the fancy cookie and redirect handling
                            # that treq.request gives: just use the raw Agent.

                            # To preserve the logging context, the timeout is treated
                            # in a similar way to `defer.gatherResults`:
                            # * Each logging context-preserving fork is wrapped in
                            #   `run_in_background`. In this case there is only one,
                            #   since the timeout fork is not logging-context aware.
                            # * The `Deferred` that joins the forks back together is
                            #   wrapped in `make_deferred_yieldable` to restore the
                            #   logging context regardless of the path taken.
                            request_deferred = run_in_background(
                                self.agent.request,
                                method_bytes,
                                url_bytes,
                                headers=Headers(headers_dict),
                                bodyProducer=producer,
                            )
                            request_deferred = timeout_deferred(
                                request_deferred,
                                timeout=_sec_timeout,
                                reactor=self.reactor,
                            )

                            response = await make_deferred_yieldable(request_deferred)
                    except DNSLookupError as e:
                        raise RequestSendFailed(e, can_retry=retry_on_dns_fail) from e
                    except Exception as e:
                        raise RequestSendFailed(e, can_retry=True) from e

                    incoming_responses_counter.labels(
                        request.method, response.code
                    ).inc()

                    set_tag(tags.HTTP_STATUS_CODE, response.code)
                    response_phrase = response.phrase.decode("ascii", errors="replace")

                    if 200 <= response.code < 300:
                        logger.debug(
                            "{%s} [%s] Got response headers: %d %s",
                            request.txn_id,
                            request.destination,
                            response.code,
                            response_phrase,
                        )
                    else:
                        logger.info(
                            "{%s} [%s] Got response headers: %d %s",
                            request.txn_id,
                            request.destination,
                            response.code,
                            response_phrase,
                        )
                        # :'(
                        # Update transactions table?
                        d = treq.content(response)
                        d = timeout_deferred(
                            d, timeout=_sec_timeout, reactor=self.reactor
                        )

                        try:
                            body = await make_deferred_yieldable(d)
                        except Exception as e:
                            # Eh, we're already going to raise an exception so lets
                            # ignore if this fails.
                            logger.warning(
                                "{%s} [%s] Failed to get error response: %s %s: %s",
                                request.txn_id,
                                request.destination,
                                request.method,
                                url_str,
                                _flatten_response_never_received(e),
                            )
                            body = None

                        exc = HttpResponseException(
                            response.code, response_phrase, body
                        )

                        # Retry if the error is a 5xx or a 429 (Too Many
                        # Requests), otherwise just raise a standard
                        # `HttpResponseException`
                        if 500 <= response.code < 600 or response.code == 429:
                            raise RequestSendFailed(exc, can_retry=True) from exc
                        else:
                            raise exc

                    break
                except RequestSendFailed as e:
                    logger.info(
                        "{%s} [%s] Request failed: %s %s: %s",
                        request.txn_id,
                        request.destination,
                        request.method,
                        url_str,
                        _flatten_response_never_received(e.inner_exception),
                    )

                    if not e.can_retry:
                        raise

                    if retries_left and not timeout:
                        if long_retries:
                            delay = 4 ** (MAX_LONG_RETRIES + 1 - retries_left)
                            delay = min(delay, 60)
                            delay *= random.uniform(0.8, 1.4)
                        else:
                            delay = 0.5 * 2 ** (MAX_SHORT_RETRIES - retries_left)
                            delay = min(delay, 2)
                            delay *= random.uniform(0.8, 1.4)

                        logger.debug(
                            "{%s} [%s] Waiting %ss before re-sending...",
                            request.txn_id,
                            request.destination,
                            delay,
                        )

                        # Sleep for the calculated delay, or wake up immediately
                        # if we get notified that the server is back up.
                        await self._sleeper.sleep(request.destination, delay * 1000)
                        retries_left -= 1
                    else:
                        raise

                except Exception as e:
                    logger.warning(
                        "{%s} [%s] Request failed: %s %s: %s",
                        request.txn_id,
                        request.destination,
                        request.method,
                        url_str,
                        _flatten_response_never_received(e),
                    )
                    raise
        return response

    def build_auth_headers(
        self,
        destination: Optional[bytes],
        method: bytes,
        url_bytes: bytes,
        content: Optional[JsonDict] = None,
        destination_is: Optional[bytes] = None,
    ) -> List[bytes]:
        """
        Builds the Authorization headers for a federation request
        Args:
            destination: The destination homeserver of the request.
                May be None if the destination is an identity server, in which case
                destination_is must be non-None.
            method: The HTTP method of the request
            url_bytes: The URI path of the request
            content: The body of the request
            destination_is: As 'destination', but if the destination is an
                identity server

        Returns:
            A list of headers to be added as "Authorization:" headers
        """
        if not destination and not destination_is:
            raise ValueError(
                "At least one of the arguments destination and destination_is "
                "must be a nonempty bytestring."
            )

        request: JsonDict = {
            "method": method.decode("ascii"),
            "uri": url_bytes.decode("ascii"),
            "origin": self.server_name,
        }

        if destination is not None:
            request["destination"] = destination.decode("ascii")

        if destination_is is not None:
            request["destination_is"] = destination_is.decode("ascii")

        if content is not None:
            request["content"] = content

        request = sign_json(request, self.server_name, self.signing_key)

        auth_headers = []

        for key, sig in request["signatures"][self.server_name].items():
            auth_headers.append(
                (
                    'X-Matrix origin="%s",key="%s",sig="%s",destination="%s"'
                    % (
                        self.server_name,
                        key,
                        sig,
                        request.get("destination") or request["destination_is"],
                    )
                ).encode("ascii")
            )
        return auth_headers

    @overload
    async def put_json(
        self,
        destination: str,
        path: str,
        args: Optional[QueryParams] = None,
        data: Optional[JsonDict] = None,
        json_data_callback: Optional[Callable[[], JsonDict]] = None,
        long_retries: bool = False,
        timeout: Optional[int] = None,
        ignore_backoff: bool = False,
        backoff_on_404: bool = False,
        try_trailing_slash_on_400: bool = False,
        parser: Literal[None] = None,
    ) -> Union[JsonDict, list]:
        ...

    @overload
    async def put_json(
        self,
        destination: str,
        path: str,
        args: Optional[QueryParams] = None,
        data: Optional[JsonDict] = None,
        json_data_callback: Optional[Callable[[], JsonDict]] = None,
        long_retries: bool = False,
        timeout: Optional[int] = None,
        ignore_backoff: bool = False,
        backoff_on_404: bool = False,
        try_trailing_slash_on_400: bool = False,
        parser: Optional[ByteParser[T]] = None,
    ) -> T:
        ...

    async def put_json(
        self,
        destination: str,
        path: str,
        args: Optional[QueryParams] = None,
        data: Optional[JsonDict] = None,
        json_data_callback: Optional[Callable[[], JsonDict]] = None,
        long_retries: bool = False,
        timeout: Optional[int] = None,
        ignore_backoff: bool = False,
        backoff_on_404: bool = False,
        try_trailing_slash_on_400: bool = False,
        parser: Optional[ByteParser] = None,
    ):
        """Sends the specified json data using PUT

        Args:
            destination: The remote server to send the HTTP request to.
            path: The HTTP path.
            args: query params
            data: A dict containing the data that will be used as
                the request body. This will be encoded as JSON.
            json_data_callback: A callable returning the dict to
                use as the request body.

            long_retries: whether to use the long retry algorithm. See
                docs on _send_request for details.

            timeout: number of milliseconds to wait for the response.
                self._default_timeout (60s) by default.

                Note that we may make several attempts to send the request; this
                timeout applies to the time spent waiting for response headers for
                *each* attempt (including connection time) as well as the time spent
                reading the response body after a 200 response.

            ignore_backoff: true to ignore the historical backoff data
                and try the request anyway.
            backoff_on_404: True if we should count a 404 response as
                a failure of the server (and should therefore back off future
                requests).
            try_trailing_slash_on_400: True if on a 400 M_UNRECOGNIZED
                response we should try appending a trailing slash to the end
                of the request. Workaround for #3622 in Synapse <= v0.99.3. This
                will be attempted before backing off if backing off has been
                enabled.
            parser: The parser to use to decode the response. Defaults to
                parsing as JSON.

        Returns:
            Succeeds when we get a 2xx HTTP response. The
            result will be the decoded JSON body.

        Raises:
            HttpResponseException: If we get an HTTP response code >= 300
                (except 429).
            NotRetryingDestination: If we are not yet ready to retry this
                server.
            FederationDeniedError: If this destination  is not on our
                federation whitelist
            RequestSendFailed: If there were problems connecting to the
                remote, due to e.g. DNS failures, connection timeouts etc.
        """
        request = MatrixFederationRequest(
            method="PUT",
            destination=destination,
            path=path,
            query=args,
            json_callback=json_data_callback,
            json=data,
        )

        start_ms = self.clock.time_msec()

        response = await self._send_request_with_optional_trailing_slash(
            request,
            try_trailing_slash_on_400,
            backoff_on_404=backoff_on_404,
            ignore_backoff=ignore_backoff,
            long_retries=long_retries,
            timeout=timeout,
        )

        if timeout is not None:
            _sec_timeout = timeout / 1000
        else:
            _sec_timeout = self.default_timeout

        if parser is None:
            parser = JsonParser()

        body = await _handle_response(
            self.reactor,
            _sec_timeout,
            request,
            response,
            start_ms,
            parser=parser,
        )

        return body

    async def post_json(
        self,
        destination: str,
        path: str,
        data: Optional[JsonDict] = None,
        long_retries: bool = False,
        timeout: Optional[int] = None,
        ignore_backoff: bool = False,
        args: Optional[QueryParams] = None,
    ) -> Union[JsonDict, list]:
        """Sends the specified json data using POST

        Args:
            destination: The remote server to send the HTTP request to.

            path: The HTTP path.

            data: A dict containing the data that will be used as
                the request body. This will be encoded as JSON.

            long_retries: whether to use the long retry algorithm. See
                docs on _send_request for details.

            timeout: number of milliseconds to wait for the response.
                self._default_timeout (60s) by default.

                Note that we may make several attempts to send the request; this
                timeout applies to the time spent waiting for response headers for
                *each* attempt (including connection time) as well as the time spent
                reading the response body after a 200 response.

            ignore_backoff: true to ignore the historical backoff data and
                try the request anyway.

            args: query params
        Returns:
            dict|list: Succeeds when we get a 2xx HTTP response. The
            result will be the decoded JSON body.

        Raises:
            HttpResponseException: If we get an HTTP response code >= 300
                (except 429).
            NotRetryingDestination: If we are not yet ready to retry this
                server.
            FederationDeniedError: If this destination  is not on our
                federation whitelist
            RequestSendFailed: If there were problems connecting to the
                remote, due to e.g. DNS failures, connection timeouts etc.
        """

        request = MatrixFederationRequest(
            method="POST", destination=destination, path=path, query=args, json=data
        )

        start_ms = self.clock.time_msec()

        response = await self._send_request(
            request,
            long_retries=long_retries,
            timeout=timeout,
            ignore_backoff=ignore_backoff,
        )

        if timeout:
            _sec_timeout = timeout / 1000
        else:
            _sec_timeout = self.default_timeout

        body = await _handle_response(
            self.reactor, _sec_timeout, request, response, start_ms, parser=JsonParser()
        )
        return body

    @overload
    async def get_json(
        self,
        destination: str,
        path: str,
        args: Optional[QueryParams] = None,
        retry_on_dns_fail: bool = True,
        timeout: Optional[int] = None,
        ignore_backoff: bool = False,
        try_trailing_slash_on_400: bool = False,
        parser: Literal[None] = None,
    ) -> Union[JsonDict, list]:
        ...

    @overload
    async def get_json(
        self,
        destination: str,
        path: str,
        args: Optional[QueryParams] = ...,
        retry_on_dns_fail: bool = ...,
        timeout: Optional[int] = ...,
        ignore_backoff: bool = ...,
        try_trailing_slash_on_400: bool = ...,
        parser: ByteParser[T] = ...,
    ) -> T:
        ...

    async def get_json(
        self,
        destination: str,
        path: str,
        args: Optional[QueryParams] = None,
        retry_on_dns_fail: bool = True,
        timeout: Optional[int] = None,
        ignore_backoff: bool = False,
        try_trailing_slash_on_400: bool = False,
        parser: Optional[ByteParser] = None,
    ):
        """GETs some json from the given host homeserver and path

        Args:
            destination: The remote server to send the HTTP request to.

            path: The HTTP path.

            args: A dictionary used to create query strings, defaults to
                None.

            timeout: number of milliseconds to wait for the response.
                self._default_timeout (60s) by default.

                Note that we may make several attempts to send the request; this
                timeout applies to the time spent waiting for response headers for
                *each* attempt (including connection time) as well as the time spent
                reading the response body after a 200 response.

            ignore_backoff: true to ignore the historical backoff data
                and try the request anyway.

            try_trailing_slash_on_400: True if on a 400 M_UNRECOGNIZED
                response we should try appending a trailing slash to the end of
                the request. Workaround for #3622 in Synapse <= v0.99.3.

            parser: The parser to use to decode the response. Defaults to
                parsing as JSON.

        Returns:
            Succeeds when we get a 2xx HTTP response. The
            result will be the decoded JSON body.

        Raises:
            HttpResponseException: If we get an HTTP response code >= 300
                (except 429).
            NotRetryingDestination: If we are not yet ready to retry this
                server.
            FederationDeniedError: If this destination  is not on our
                federation whitelist
            RequestSendFailed: If there were problems connecting to the
                remote, due to e.g. DNS failures, connection timeouts etc.
        """
        request = MatrixFederationRequest(
            method="GET", destination=destination, path=path, query=args
        )

        start_ms = self.clock.time_msec()

        response = await self._send_request_with_optional_trailing_slash(
            request,
            try_trailing_slash_on_400,
            backoff_on_404=False,
            ignore_backoff=ignore_backoff,
            retry_on_dns_fail=retry_on_dns_fail,
            timeout=timeout,
        )

        if timeout is not None:
            _sec_timeout = timeout / 1000
        else:
            _sec_timeout = self.default_timeout

        if parser is None:
            parser = JsonParser()

        body = await _handle_response(
            self.reactor,
            _sec_timeout,
            request,
            response,
            start_ms,
            parser=parser,
        )

        return body

    async def delete_json(
        self,
        destination: str,
        path: str,
        long_retries: bool = False,
        timeout: Optional[int] = None,
        ignore_backoff: bool = False,
        args: Optional[QueryParams] = None,
    ) -> Union[JsonDict, list]:
        """Send a DELETE request to the remote expecting some json response

        Args:
            destination: The remote server to send the HTTP request to.
            path: The HTTP path.

            long_retries: whether to use the long retry algorithm. See
                docs on _send_request for details.

            timeout: number of milliseconds to wait for the response.
                self._default_timeout (60s) by default.

                Note that we may make several attempts to send the request; this
                timeout applies to the time spent waiting for response headers for
                *each* attempt (including connection time) as well as the time spent
                reading the response body after a 200 response.

            ignore_backoff: true to ignore the historical backoff data and
                try the request anyway.

            args: query params
        Returns:
            Succeeds when we get a 2xx HTTP response. The
            result will be the decoded JSON body.

        Raises:
            HttpResponseException: If we get an HTTP response code >= 300
                (except 429).
            NotRetryingDestination: If we are not yet ready to retry this
                server.
            FederationDeniedError: If this destination  is not on our
                federation whitelist
            RequestSendFailed: If there were problems connecting to the
                remote, due to e.g. DNS failures, connection timeouts etc.
        """
        request = MatrixFederationRequest(
            method="DELETE", destination=destination, path=path, query=args
        )

        start_ms = self.clock.time_msec()

        response = await self._send_request(
            request,
            long_retries=long_retries,
            timeout=timeout,
            ignore_backoff=ignore_backoff,
        )

        if timeout is not None:
            _sec_timeout = timeout / 1000
        else:
            _sec_timeout = self.default_timeout

        body = await _handle_response(
            self.reactor, _sec_timeout, request, response, start_ms, parser=JsonParser()
        )
        return body

    async def get_file(
        self,
        destination: str,
        path: str,
        output_stream: BinaryIO,
        args: Optional[QueryParams] = None,
        retry_on_dns_fail: bool = True,
        max_size: Optional[int] = None,
        ignore_backoff: bool = False,
    ) -> Tuple[int, Dict[bytes, List[bytes]]]:
        """GETs a file from a given homeserver
        Args:
            destination: The remote server to send the HTTP request to.
            path: The HTTP path to GET.
            output_stream: File to write the response body to.
            args: Optional dictionary used to create the query string.
            ignore_backoff: true to ignore the historical backoff data
                and try the request anyway.

        Returns:
            Resolves with an (int,dict) tuple of
            the file length and a dict of the response headers.

        Raises:
            HttpResponseException: If we get an HTTP response code >= 300
                (except 429).
            NotRetryingDestination: If we are not yet ready to retry this
                server.
            FederationDeniedError: If this destination  is not on our
                federation whitelist
            RequestSendFailed: If there were problems connecting to the
                remote, due to e.g. DNS failures, connection timeouts etc.
        """
        request = MatrixFederationRequest(
            method="GET", destination=destination, path=path, query=args
        )

        response = await self._send_request(
            request, retry_on_dns_fail=retry_on_dns_fail, ignore_backoff=ignore_backoff
        )

        headers = dict(response.headers.getAllRawHeaders())

        try:
            d = read_body_with_max_size(response, output_stream, max_size)
            d.addTimeout(self.default_timeout, self.reactor)
            length = await make_deferred_yieldable(d)
        except BodyExceededMaxSize:
            msg = "Requested file is too large > %r bytes" % (max_size,)
            logger.warning(
                "{%s} [%s] %s",
                request.txn_id,
                request.destination,
                msg,
            )
            raise SynapseError(HTTPStatus.BAD_GATEWAY, msg, Codes.TOO_LARGE)
        except defer.TimeoutError as e:
            logger.warning(
                "{%s} [%s] Timed out reading response - %s %s",
                request.txn_id,
                request.destination,
                request.method,
                request.uri.decode("ascii"),
            )
            raise RequestSendFailed(e, can_retry=True) from e
        except ResponseFailed as e:
            logger.warning(
                "{%s} [%s] Failed to read response - %s %s",
                request.txn_id,
                request.destination,
                request.method,
                request.uri.decode("ascii"),
            )
            raise RequestSendFailed(e, can_retry=True) from e
        except Exception as e:
            logger.warning(
                "{%s} [%s] Error reading response: %s",
                request.txn_id,
                request.destination,
                e,
            )
            raise
        logger.info(
            "{%s} [%s] Completed: %d %s [%d bytes] %s %s",
            request.txn_id,
            request.destination,
            response.code,
            response.phrase.decode("ascii", errors="replace"),
            length,
            request.method,
            request.uri.decode("ascii"),
        )
        return length, headers


def _flatten_response_never_received(e: BaseException) -> str:
    if hasattr(e, "reasons"):
        reasons = ", ".join(
            _flatten_response_never_received(f.value) for f in e.reasons  # type: ignore[attr-defined]
        )

        return "%s:[%s]" % (type(e).__name__, reasons)
    else:
        return repr(e)


def check_content_type_is(headers: Headers, expected_content_type: str) -> None:
    """
    Check that a set of HTTP headers have a Content-Type header, and that it
    is the expected value..

    Args:
        headers: headers to check

    Raises:
        RequestSendFailed: if the Content-Type header is missing or doesn't match

    """
    content_type_headers = headers.getRawHeaders(b"Content-Type")
    if content_type_headers is None:
        raise RequestSendFailed(
            RuntimeError("No Content-Type header received from remote server"),
            can_retry=False,
        )

    c_type = content_type_headers[0].decode("ascii")  # only the first header
    val, options = cgi.parse_header(c_type)
    if val != expected_content_type:
        raise RequestSendFailed(
            RuntimeError(
                f"Remote server sent Content-Type header of '{c_type}', not '{expected_content_type}'",
            ),
            can_retry=False,
        )
