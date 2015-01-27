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

"""This module contains REST servlets to do with registration: /register"""

from base import AppServiceRestServlet, as_path_pattern
from synapse.api.errors import CodeMessageException

import logging

logger = logging.getLogger(__name__)


class RegisterRestServlet(AppServiceRestServlet):
    """Handles AS registration with the home server.
    """

    PATTERN = as_path_pattern("/register$")

    def on_POST(self, request):
        raise CodeMessageException(500, "Not implemented")


def register_servlets(hs, http_server):
    RegisterRestServlet(hs).register(http_server)