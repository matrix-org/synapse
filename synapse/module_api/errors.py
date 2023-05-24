# Copyright 2020 The Matrix.org Foundation C.I.C.
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

"""Exception types which are exposed as part of the stable module API"""
import attr

from synapse.api.errors import (
    Codes,
    InvalidClientCredentialsError,
    RedirectException,
    SynapseError,
)
from synapse.config._base import ConfigError
from synapse.handlers.push_rules import InvalidRuleException
from synapse.storage.push_rule import RuleNotFoundException


@attr.s(auto_attribs=True)
class FederationHttpResponseException(Exception):
    """
    Raised when an HTTP request over federation returns a status code > 300 (and not 429).
    """

    remote_server_name: str
    # The HTTP status code of the response.
    status_code: int
    # A human-readable explanation for the error.
    msg: str
    # The non-parsed HTTP response body.
    response_body: bytes


@attr.s(auto_attribs=True)
class FederationHttpNotRetryingDestinationException(Exception):
    """
    Raised when the local homeserver refuses to send traffic to a remote homeserver that
    it believes is experiencing an outage.
    """

    remote_server_name: str


@attr.s(auto_attribs=True)
class FederationHttpDeniedException(Exception):
    """
    Raised when the local homeserver refuses to send federation traffic to a remote
    homeserver. This is due to the remote homeserver not being on the configured
    federation whitelist.
    """

    remote_server_name: str


@attr.s(auto_attribs=True)
class FederationHttpRequestSendFailedException(Exception):
    """
    Raised when there are problems connecting to the remote homeserver due to e.g.
    DNS failures, connection timeouts, etc.
    """

    remote_server_name: str
    # Whether the request can be retried with a chance of success. This will be True
    # if the failure occurred due to e.g. timeouts, a disruption in the connection etc.
    # Will be false in the case of e.g. a malformed response from the remote homeserver.
    can_retry: bool


__all__ = [
    "Codes",
    "InvalidClientCredentialsError",
    "RedirectException",
    "SynapseError",
    "ConfigError",
    "InvalidRuleException",
    "RuleNotFoundException",
    "FederationHttpResponseException",
    "FederationHttpNotRetryingDestinationException",
    "FederationHttpDeniedException",
    "FederationHttpRequestSendFailedException",
]
