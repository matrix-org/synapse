# -*- coding: utf-8 -*-
# Copyright 2018 New Vector Ltd
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
import logging
import re
import urllib
from inspect import signature
from typing import TYPE_CHECKING, Dict, List, Tuple

from prometheus_client import Counter, Gauge

from synapse.api.errors import HttpResponseException, SynapseError
from synapse.http import RequestTimedOutError
from synapse.logging.opentracing import inject_active_span_byte_dict, trace
from synapse.util.caches.response_cache import ResponseCache
from synapse.util.stringutils import random_string

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

_pending_outgoing_requests = Gauge(
    "synapse_pending_outgoing_replication_requests",
    "Number of active outgoing replication requests, by replication method name",
    ["name"],
)

_outgoing_request_counter = Counter(
    "synapse_outgoing_replication_requests",
    "Number of outgoing replication requests, by replication method name and result",
    ["name", "code"],
)


class ReplicationEndpoint(metaclass=abc.ABCMeta):
    """Helper base class for defining new replication HTTP endpoints.

    This creates an endpoint under `/_synapse/replication/:NAME/:PATH_ARGS..`
    (with a `/:txn_id` suffix for cached requests), where NAME is a name,
    PATH_ARGS are a tuple of parameters to be encoded in the URL.

    For example, if `NAME` is "send_event" and `PATH_ARGS` is `("event_id",)`,
    with `CACHE` set to true then this generates an endpoint:

        /_synapse/replication/send_event/:event_id/:txn_id

    For POST/PUT requests the payload is serialized to json and sent as the
    body, while for GET requests the payload is added as query parameters. See
    `_serialize_payload` for details.

    Incoming requests are handled by overriding `_handle_request`. Servers
    must call `register` to register the path with the HTTP server.

    Requests can be sent by calling the client returned by `make_client`.
    Requests are sent to master process by default, but can be sent to other
    named processes by specifying an `instance_name` keyword argument.

    Attributes:
        NAME (str): A name for the endpoint, added to the path as well as used
            in logging and metrics.
        PATH_ARGS (tuple[str]): A list of parameters to be added to the path.
            Adding parameters to the path (rather than payload) can make it
            easier to follow along in the log files.
        METHOD (str): The method of the HTTP request, defaults to POST. Can be
            one of POST, PUT or GET. If GET then the payload is sent as query
            parameters rather than a JSON body.
        CACHE (bool): Whether server should cache the result of the request/
            If true then transparently adds a txn_id to all requests, and
            `_handle_request` must return a Deferred.
        RETRY_ON_TIMEOUT(bool): Whether or not to retry the request when a 504
            is received.
    """

    NAME = abc.abstractproperty()  # type: str  # type: ignore
    PATH_ARGS = abc.abstractproperty()  # type: Tuple[str, ...]  # type: ignore
    METHOD = "POST"
    CACHE = True
    RETRY_ON_TIMEOUT = True

    def __init__(self, hs: "HomeServer"):
        if self.CACHE:
            self.response_cache = ResponseCache(
                hs.get_clock(), "repl." + self.NAME, timeout_ms=30 * 60 * 1000
            )  # type: ResponseCache[str]

        # We reserve `instance_name` as a parameter to sending requests, so we
        # assert here that sub classes don't try and use the name.
        assert (
            "instance_name" not in self.PATH_ARGS
        ), "`instance_name` is a reserved parameter name"
        assert (
            "instance_name"
            not in signature(self.__class__._serialize_payload).parameters
        ), "`instance_name` is a reserved parameter name"

        assert self.METHOD in ("PUT", "POST", "GET")

        self._replication_secret = None
        if hs.config.worker.worker_replication_secret:
            self._replication_secret = hs.config.worker.worker_replication_secret

    def _check_auth(self, request) -> None:
        # Get the authorization header.
        auth_headers = request.requestHeaders.getRawHeaders(b"Authorization")

        if len(auth_headers) > 1:
            raise RuntimeError("Too many Authorization headers.")
        parts = auth_headers[0].split(b" ")
        if parts[0] == b"Bearer" and len(parts) == 2:
            received_secret = parts[1].decode("ascii")
            if self._replication_secret == received_secret:
                # Success!
                return

        raise RuntimeError("Invalid Authorization header.")

    @abc.abstractmethod
    async def _serialize_payload(**kwargs):
        """Static method that is called when creating a request.

        Concrete implementations should have explicit parameters (rather than
        kwargs) so that an appropriate exception is raised if the client is
        called with unexpected parameters. All PATH_ARGS must appear in
        argument list.

        Returns:
            dict: If POST/PUT request then dictionary must be JSON serialisable,
            otherwise must be appropriate for adding as query args.
        """
        return {}

    @abc.abstractmethod
    async def _handle_request(self, request, **kwargs):
        """Handle incoming request.

        This is called with the request object and PATH_ARGS.

        Returns:
            tuple[int, dict]: HTTP status code and a JSON serialisable dict
            to be used as response body of request.
        """
        pass

    @classmethod
    def make_client(cls, hs):
        """Create a client that makes requests.

        Returns a callable that accepts the same parameters as `_serialize_payload`.
        """
        clock = hs.get_clock()
        client = hs.get_simple_http_client()
        local_instance_name = hs.get_instance_name()

        master_host = hs.config.worker_replication_host
        master_port = hs.config.worker_replication_http_port

        instance_map = hs.config.worker.instance_map

        outgoing_gauge = _pending_outgoing_requests.labels(cls.NAME)

        replication_secret = None
        if hs.config.worker.worker_replication_secret:
            replication_secret = hs.config.worker.worker_replication_secret.encode(
                "ascii"
            )

        @trace(opname="outgoing_replication_request")
        @outgoing_gauge.track_inprogress()
        async def send_request(*, instance_name="master", **kwargs):
            if instance_name == local_instance_name:
                raise Exception("Trying to send HTTP request to self")
            if instance_name == "master":
                host = master_host
                port = master_port
            elif instance_name in instance_map:
                host = instance_map[instance_name].host
                port = instance_map[instance_name].port
            else:
                raise Exception(
                    "Instance %r not in 'instance_map' config" % (instance_name,)
                )

            data = await cls._serialize_payload(**kwargs)

            url_args = [
                urllib.parse.quote(kwargs[name], safe="") for name in cls.PATH_ARGS
            ]

            if cls.CACHE:
                txn_id = random_string(10)
                url_args.append(txn_id)

            if cls.METHOD == "POST":
                request_func = client.post_json_get_json
            elif cls.METHOD == "PUT":
                request_func = client.put_json
            elif cls.METHOD == "GET":
                request_func = client.get_json
            else:
                # We have already asserted in the constructor that a
                # compatible was picked, but lets be paranoid.
                raise Exception(
                    "Unknown METHOD on %s replication endpoint" % (cls.NAME,)
                )

            uri = "http://%s:%s/_synapse/replication/%s/%s" % (
                host,
                port,
                cls.NAME,
                "/".join(url_args),
            )

            try:
                # We keep retrying the same request for timeouts. This is so that we
                # have a good idea that the request has either succeeded or failed on
                # the master, and so whether we should clean up or not.
                while True:
                    headers = {}  # type: Dict[bytes, List[bytes]]
                    # Add an authorization header, if configured.
                    if replication_secret:
                        headers[b"Authorization"] = [b"Bearer " + replication_secret]
                    inject_active_span_byte_dict(headers, None, check_destination=False)
                    try:
                        result = await request_func(uri, data, headers=headers)
                        break
                    except RequestTimedOutError:
                        if not cls.RETRY_ON_TIMEOUT:
                            raise

                    logger.warning("%s request timed out; retrying", cls.NAME)

                    # If we timed out we probably don't need to worry about backing
                    # off too much, but lets just wait a little anyway.
                    await clock.sleep(1)
            except HttpResponseException as e:
                # We convert to SynapseError as we know that it was a SynapseError
                # on the main process that we should send to the client. (And
                # importantly, not stack traces everywhere)
                _outgoing_request_counter.labels(cls.NAME, e.code).inc()
                raise e.to_synapse_error()
            except Exception as e:
                _outgoing_request_counter.labels(cls.NAME, "ERR").inc()
                raise SynapseError(502, "Failed to talk to main process") from e

            _outgoing_request_counter.labels(cls.NAME, 200).inc()
            return result

        return send_request

    def register(self, http_server):
        """Called by the server to register this as a handler to the
        appropriate path.
        """

        url_args = list(self.PATH_ARGS)
        method = self.METHOD

        if self.CACHE:
            url_args.append("txn_id")

        args = "/".join("(?P<%s>[^/]+)" % (arg,) for arg in url_args)
        pattern = re.compile("^/_synapse/replication/%s/%s$" % (self.NAME, args))

        http_server.register_paths(
            method,
            [pattern],
            self._check_auth_and_handle,
            self.__class__.__name__,
        )

    def _check_auth_and_handle(self, request, **kwargs):
        """Called on new incoming requests when caching is enabled. Checks
        if there is a cached response for the request and returns that,
        otherwise calls `_handle_request` and caches its response.
        """
        # We just use the txn_id here, but we probably also want to use the
        # other PATH_ARGS as well.

        # Check the authorization headers before handling the request.
        if self._replication_secret:
            self._check_auth(request)

        if self.CACHE:
            txn_id = kwargs.pop("txn_id")

            return self.response_cache.wrap(
                txn_id, self._handle_request, request, **kwargs
            )

        return self._handle_request(request, **kwargs)
