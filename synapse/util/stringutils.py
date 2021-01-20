# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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
import itertools
import random
import re
import string
from collections.abc import Iterable
from typing import Optional, Tuple

from synapse.api.errors import Codes, SynapseError

_string_with_symbols = string.digits + string.ascii_letters + ".,;:^&*-_+=#~@"

# https://matrix.org/docs/spec/client_server/r0.6.0#post-matrix-client-r0-register-email-requesttoken
client_secret_regex = re.compile(r"^[0-9a-zA-Z\.\=\_\-]+$")

# https://matrix.org/docs/spec/client_server/r0.6.1#matrix-content-mxc-uris,
# together with https://github.com/matrix-org/matrix-doc/issues/2177 which basically
# says "there is no grammar for media ids"
#
# The server_name part of this is purposely lax: use parse_and_validate_mxc for
# additional validation.
#
MXC_REGEX = re.compile("^mxc://([^/]+)/([^/#?]+)$")

# random_string and random_string_with_symbols are used for a range of things,
# some cryptographically important, some less so. We use SystemRandom to make sure
# we get cryptographically-secure randoms.
rand = random.SystemRandom()


def random_string(length):
    return "".join(rand.choice(string.ascii_letters) for _ in range(length))


def random_string_with_symbols(length):
    return "".join(rand.choice(_string_with_symbols) for _ in range(length))


def is_ascii(s):
    if isinstance(s, bytes):
        try:
            s.decode("ascii").encode("ascii")
        except UnicodeDecodeError:
            return False
        except UnicodeEncodeError:
            return False
        return True


def assert_valid_client_secret(client_secret):
    """Validate that a given string matches the client_secret regex defined by the spec"""
    if client_secret_regex.match(client_secret) is None:
        raise SynapseError(
            400, "Invalid client_secret parameter", errcode=Codes.INVALID_PARAM
        )


def parse_server_name(server_name: str) -> Tuple[str, Optional[int]]:
    """Split a server name into host/port parts.

    Args:
        server_name: server name to parse

    Returns:
        host/port parts.

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


def parse_and_validate_server_name(server_name: str) -> Tuple[str, Optional[int]]:
    """Split a server name into host/port parts and do some basic validation.

    Args:
        server_name: server name to parse

    Returns:
        host/port parts.

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


def parse_and_validate_mxc_uri(mxc: str) -> Tuple[str, Optional[int], str]:
    """Parse the given string as an MXC URI

    Checks that the "server name" part is a valid server name

    Args:
        mxc: the (alleged) MXC URI to be checked
    Returns:
        hostname, port, media id
    Raises:
        ValueError if the URI cannot be parsed
    """
    m = MXC_REGEX.match(mxc)
    if not m:
        raise ValueError("mxc URI %r did not match expected format" % (mxc,))
    server_name = m.group(1)
    media_id = m.group(2)
    host, port = parse_and_validate_server_name(server_name)
    return host, port, media_id


def shortstr(iterable: Iterable, maxitems: int = 5) -> str:
    """If iterable has maxitems or fewer, return the stringification of a list
    containing those items.

    Otherwise, return the stringification of a a list with the first maxitems items,
    followed by "...".

    Args:
        iterable: iterable to truncate
        maxitems: number of items to return before truncating
    """

    items = list(itertools.islice(iterable, maxitems + 1))
    if len(items) <= maxitems:
        return str(items)
    return "[" + ", ".join(repr(r) for r in items[:maxitems]) + ", ...]"


def strtobool(val: str) -> bool:
    """Convert a string representation of truth to True or False

    True values are 'y', 'yes', 't', 'true', 'on', and '1'; false values
    are 'n', 'no', 'f', 'false', 'off', and '0'.  Raises ValueError if
    'val' is anything else.

    This is lifted from distutils.util.strtobool, with the exception that it actually
    returns a bool, rather than an int.
    """
    val = val.lower()
    if val in ("y", "yes", "t", "true", "on", "1"):
        return True
    elif val in ("n", "no", "f", "false", "off", "0"):
        return False
    else:
        raise ValueError("invalid truth value %r" % (val,))
