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

import logging
import re

from twisted.internet import defer

logger = logging.getLogger(__name__)


@defer.inlineCallbacks
def check_3pid_allowed(hs, medium, address):
    """Checks whether a given format of 3PID is allowed to be used on this HS

    Args:
        hs (synapse.server.HomeServer): server
        medium (str): 3pid medium - e.g. email, msisdn
        address (str): address within that medium (e.g. "wotan@matrix.org")
            msisdns need to first have been canonicalised
    Returns:
        defered bool: whether the 3PID medium/address is allowed to be added to this HS
    """

    if hs.config.check_is_for_allowed_local_3pids:
        data = yield hs.http_client.get_json(
            "https://%s%s" % (
                hs.config.check_is_for_allowed_local_3pids,
                "/_matrix/identity/api/v1/discover_urls"
            ),
            {'medium': medium, 'address': address }
        )
        defer.returnValue(data.hs_url+"/" == self.hs.config.public_baseurl)
        return

    if hs.config.allowed_local_3pids:
        for constraint in hs.config.allowed_local_3pids:
            logger.debug(
                "Checking 3PID %s (%s) against %s (%s)",
                address, medium, constraint['pattern'], constraint['medium'],
            )
            if (
                medium == constraint['medium'] and
                re.match(constraint['pattern'], address)
            ):
                defer.returnValue(True)
                return
    else:
        defer.returnValue(True)
        return

    defer.returnValue(False)
    return
