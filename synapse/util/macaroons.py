# -*- coding: utf-8 -*-
# Copyright 2020 Quentin Gliech
# Copyright 2021 The Matrix.org Foundation C.I.C.
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

"""Utilities for manipulating macaroons"""

from typing import Callable, Optional

import pymacaroons
from pymacaroons.exceptions import MacaroonVerificationFailedException


def get_value_from_macaroon(macaroon: pymacaroons.Macaroon, key: str) -> str:
    """Extracts a caveat value from a macaroon token.

    Checks that there is exactly one caveat of the form "key = <val>" in the macaroon,
    and returns the extracted value.

    Args:
        macaroon: the token
        key: the key of the caveat to extract

    Returns:
        The extracted value

    Raises:
        MacaroonVerificationFailedException: if there are conflicting values for the
             caveat in the macaroon, or if the caveat was not found in the macaroon.
    """
    prefix = key + " = "
    result = None  # type: Optional[str]
    for caveat in macaroon.caveats:
        if not caveat.caveat_id.startswith(prefix):
            continue

        val = caveat.caveat_id[len(prefix) :]

        if result is None:
            # first time we found this caveat: record the value
            result = val
        elif val != result:
            # on subsequent occurrences, raise if the value is different.
            raise MacaroonVerificationFailedException(
                "Conflicting values for caveat " + key
            )

    if result is not None:
        return result

    # If the caveat is not there, we raise a MacaroonVerificationFailedException.
    # Note that it is insecure to generate a macaroon without all the caveats you
    # might need (because there is nothing stopping people from adding extra caveats),
    # so if the caveat isn't there, something odd must be going on.
    raise MacaroonVerificationFailedException("No %s caveat in macaroon" % (key,))


def satisfy_expiry(v: pymacaroons.Verifier, get_time_ms: Callable[[], int]) -> None:
    """Make a macaroon verifier which accepts 'time' caveats

    Builds a caveat verifier which will accept unexpired 'time' caveats, and adds it to
    the given macaroon verifier.

    Args:
        v: the macaroon verifier
        get_time_ms: a callable which will return the timestamp after which the caveat
            should be considered expired. Normally the current time.
    """

    def verify_expiry_caveat(caveat: str):
        time_msec = get_time_ms()
        prefix = "time < "
        if not caveat.startswith(prefix):
            return False
        expiry = int(caveat[len(prefix) :])
        return time_msec < expiry

    v.satisfy_general(verify_expiry_caveat)
