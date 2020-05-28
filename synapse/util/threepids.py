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
    """Checks whether a given 3PID is allowed to be used on this HS

    Args:
        hs (synapse.server.HomeServer): server
        medium (str): 3pid medium - e.g. email, msisdn
        address (str): address within that medium (e.g. "wotan@matrix.org")
            msisdns need to first have been canonicalised
    Returns:
        defered bool: whether the 3PID medium/address is allowed to be added to this HS
    """

    if hs.config.check_is_for_allowed_local_3pids:
        data = yield hs.get_simple_http_client().get_json(
            "https://%s%s"
            % (
                hs.config.check_is_for_allowed_local_3pids,
                "/_matrix/identity/api/v1/internal-info",
            ),
            {"medium": medium, "address": address},
        )

        # Check for invalid response
        if "hs" not in data and "shadow_hs" not in data:
            defer.returnValue(False)

        # Check if this user is intended to register for this homeserver
        if (
            data.get("hs") != hs.config.server_name
            and data.get("shadow_hs") != hs.config.server_name
        ):
            defer.returnValue(False)

        if data.get("requires_invite", False) and not data.get("invited", False):
            # Requires an invite but hasn't been invited
            defer.returnValue(False)

        defer.returnValue(True)

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
                defer.returnValue(True)
    else:
        defer.returnValue(True)

    defer.returnValue(False)
