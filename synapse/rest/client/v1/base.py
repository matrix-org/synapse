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

"""This module contains base REST classes for constructing client v1 servlets.
"""

from synapse.http.servlet import RestServlet
from synapse.api.urls import CLIENT_PREFIX
from synapse.rest.client.transactions import HttpTransactionCache

import re

import logging


logger = logging.getLogger(__name__)


def client_path_patterns(path_regex, releases=(0,), include_in_unstable=True):
    """Creates a regex compiled client path with the correct client path
    prefix.

    Args:
        path_regex (str): The regex string to match. This should NOT have a ^
        as this will be prefixed.
    Returns:
        SRE_Pattern
    """
    patterns = [re.compile("^" + CLIENT_PREFIX + path_regex)]
    if include_in_unstable:
        unstable_prefix = CLIENT_PREFIX.replace("/api/v1", "/unstable")
        patterns.append(re.compile("^" + unstable_prefix + path_regex))
    for release in releases:
        new_prefix = CLIENT_PREFIX.replace("/api/v1", "/r%d" % release)
        patterns.append(re.compile("^" + new_prefix + path_regex))
    return patterns


class ClientV1RestServlet(RestServlet):
    """A base Synapse REST Servlet for the client version 1 API.
    """

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer):
        """
        self.hs = hs
        self.builder_factory = hs.get_event_builder_factory()
        self.auth = hs.get_v1auth()
        self.txns = HttpTransactionCache(hs.get_clock())
