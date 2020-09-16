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

from synapse.api.errors import Codes, SynapseError

_string_with_symbols = string.digits + string.ascii_letters + ".,;:^&*-_+=#~@"

# https://matrix.org/docs/spec/client_server/r0.6.0#post-matrix-client-r0-register-email-requesttoken
client_secret_regex = re.compile(r"^[0-9a-zA-Z\.\=\_\-]+$")

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
