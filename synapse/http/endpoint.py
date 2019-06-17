# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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
import re

logger = logging.getLogger(__name__)


def parse_server_name(server_name):
    """Split a server name into host/port parts.

    Args:
        server_name (str): server name to parse

    Returns:
        Tuple[str, int|None]: host/port parts.

    Raises:
        ValueError if the server name could not be parsed.
    """
    try:
        if server_name[-1] == "]":
            # ipv6 literal, hopefully
            return server_name, None

        domain_port = server_name.rsplit(":", 1)
        domain = domain_port[0]
        port = int(domain_port[1]) if domain_port[1:] else None
        return domain, port
    except Exception:
        raise ValueError("Invalid server name '%s'" % server_name)


VALID_HOST_REGEX = re.compile("\\A[0-9a-zA-Z.-]+\\Z")


def parse_and_validate_server_name(server_name):
    """Split a server name into host/port parts and do some basic validation.

    Args:
        server_name (str): server name to parse

    Returns:
        Tuple[str, int|None]: host/port parts.

    Raises:
        ValueError if the server name could not be parsed.
    """
    host, port = parse_server_name(server_name)

    # these tests don't need to be bulletproof as we'll find out soon enough
    # if somebody is giving us invalid data. What we *do* need is to be sure
    # that nobody is sneaking IP literals in that look like hostnames, etc.

    # look for ipv6 literals
    if host[0] == "[":
        if host[-1] != "]":
            raise ValueError("Mismatched [...] in server name '%s'" % (server_name,))
        return host, port

    # otherwise it should only be alphanumerics.
    if not VALID_HOST_REGEX.match(host):
        raise ValueError(
            "Server name '%s' contains invalid characters" % (server_name,)
        )

    return host, port
