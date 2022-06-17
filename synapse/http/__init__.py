# Copyright 2014-2016 OpenMarket Ltd
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
import re
from typing import Union

from twisted.internet import address, task
from twisted.web.client import FileBodyProducer
from twisted.web.iweb import IRequest

from synapse.api.errors import MissingClientTokenError, SynapseError


class RequestTimedOutError(SynapseError):
    """Exception representing timeout of an outbound request"""

    def __init__(self, msg: str):
        super().__init__(504, msg)


ACCESS_TOKEN_RE = re.compile(r"(\?.*access(_|%5[Ff])token=)[^&]*(.*)$")
CLIENT_SECRET_RE = re.compile(r"(\?.*client(_|%5[Ff])secret=)[^&]*(.*)$")


def redact_uri(uri: str) -> str:
    """Strips sensitive information from the uri replaces with <redacted>"""
    uri = ACCESS_TOKEN_RE.sub(r"\1<redacted>\3", uri)
    return CLIENT_SECRET_RE.sub(r"\1<redacted>\3", uri)


class QuieterFileBodyProducer(FileBodyProducer):
    """Wrapper for FileBodyProducer that avoids CRITICAL errors when the connection drops.

    Workaround for https://github.com/matrix-org/synapse/issues/4003 /
    https://twistedmatrix.com/trac/ticket/6528
    """

    def stopProducing(self) -> None:
        try:
            FileBodyProducer.stopProducing(self)
        except task.TaskStopped:
            pass


def get_request_uri(request: IRequest) -> bytes:
    """Return the full URI that was requested by the client"""
    return b"%s://%s%s" % (
        b"https" if request.isSecure() else b"http",
        _get_requested_host(request),
        # despite its name, "request.uri" is only the path and query-string.
        request.uri,
    )


def _get_requested_host(request: IRequest) -> bytes:
    hostname = request.getHeader(b"host")
    if hostname:
        return hostname

    # no Host header, use the address/port that the request arrived on
    host: Union[address.IPv4Address, address.IPv6Address] = request.getHost()

    hostname = host.host.encode("ascii")

    if request.isSecure() and host.port == 443:
        # default port for https
        return hostname

    if not request.isSecure() and host.port == 80:
        # default port for http
        return hostname

    return b"%s:%i" % (
        hostname,
        host.port,
    )


def get_request_user_agent(request: IRequest, default: str = "") -> str:
    """Return the last User-Agent header, or the given default."""
    # There could be raw utf-8 bytes in the User-Agent header.

    # N.B. if you don't do this, the logger explodes cryptically
    # with maximum recursion trying to log errors about
    # the charset problem.
    # c.f. https://github.com/matrix-org/synapse/issues/3471

    h = request.getHeader(b"User-Agent")
    return h.decode("ascii", "replace") if h else default


def request_has_access_token(request: IRequest) -> bool:
    """Checks if the request has an access_token.

    Returns:
        False if no access_token was given, True otherwise.
    """
    # This will always be set by the time Twisted calls us.
    assert request.args is not None

    query_params = request.args.get(b"access_token")
    auth_headers = request.requestHeaders.getRawHeaders(b"Authorization")
    return bool(query_params) or bool(auth_headers)


def get_request_access_token(request: IRequest) -> str:
    """Extracts the access_token from the request.

    Args:
        request: The http request.
    Returns:
        The access_token
    Raises:
        MissingClientTokenError: If there isn't a single access_token in the
            request
    """
    # This will always be set by the time Twisted calls us.
    assert request.args is not None

    auth_headers = request.requestHeaders.getRawHeaders(b"Authorization")
    query_params = request.args.get(b"access_token")
    if auth_headers:
        # Try the get the access_token from a "Authorization: Bearer"
        # header
        if query_params is not None:
            raise MissingClientTokenError(
                "Mixing Authorization headers and access_token query parameters."
            )
        if len(auth_headers) > 1:
            raise MissingClientTokenError("Too many Authorization headers.")
        parts = auth_headers[0].split(b" ")
        if parts[0] == b"Bearer" and len(parts) == 2:
            return parts[1].decode("ascii")
        else:
            raise MissingClientTokenError("Invalid Authorization header.")
    else:
        # Try to get the access_token from the query params.
        if not query_params:
            raise MissingClientTokenError()

        return query_params[0].decode("ascii")
