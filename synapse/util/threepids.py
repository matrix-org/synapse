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

import email.utils
import logging
import re

from synapse.api.errors import SynapseError

logger = logging.getLogger(__name__)


def check_3pid_allowed(hs, medium, address):
    """Checks whether a given format of 3PID is allowed to be used on this HS

    Args:
        hs (synapse.server.HomeServer): server
        medium (str): 3pid medium - e.g. email, msisdn
        address (str): address within that medium (e.g. "wotan@matrix.org")
            msisdns need to first have been canonicalised
    Returns:
        bool: whether the 3PID medium/address is allowed to be added to this HS
    """

    if hs.config.allowed_local_3pids:
        for constraint in hs.config.allowed_local_3pids:
            logger.debug(
                "Checking 3PID %s (%s) against %s (%s)",
                address,
                medium,
                constraint["pattern"],
                constraint["medium"],
            )
            if medium == constraint["medium"] and re.match(
                constraint["pattern"], address
            ):
                return True
    else:
        return True

    return False


def canonicalise_email(address) -> str:
    """'Canonicalise' email address
    Case folding of local part of email address and lowercase domain part
    See MSC2265, https://github.com/matrix-org/matrix-doc/pull/2265

    Args:
        address (str): email address within that medium (e.g. "wotan@matrix.org")
    Returns:
        (str) The canonical form of the email address
    Raises:
        SynapseError if the address could not be parsed.
    """

    address = address.strip()
    # Validate address
    # See https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-11340
    parsedAddress = email.utils.parseaddr(address)[1]

    # parseaddr does not find missing "@"
    regex = r"^[^@]+@[^@]+\.[^@]+$"
    if parsedAddress == "" or not bool(re.fullmatch(regex, address)):
        logger.debug("Couldn't parse email address %s", address)
        raise SynapseError(400, "Unable to parse email address")
    address = address.split("@")
    return address[0].casefold() + "@" + address[1].lower()
