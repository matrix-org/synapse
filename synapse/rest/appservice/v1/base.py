# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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
from synapse.api.urls import APP_SERVICE_PREFIX
import re

import logging


logger = logging.getLogger(__name__)


def as_path_pattern(path_regex):
    """Creates a regex compiled appservice path with the correct path
    prefix.

    Args:
        path_regex (str): The regex string to match. This should NOT have a ^
        as this will be prefixed.
    Returns:
        SRE_Pattern
    """
    return re.compile("^" + APP_SERVICE_PREFIX + path_regex)


class AppServiceRestServlet(RestServlet):
    """A base Synapse REST Servlet for the application services version 1 API.
    """

    def __init__(self, hs):
        self.hs = hs
        self.handler = hs.get_handlers().appservice_handler
