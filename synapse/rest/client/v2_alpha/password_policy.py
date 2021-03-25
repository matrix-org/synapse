# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.
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

from synapse.http.servlet import RestServlet

from ._base import client_patterns

logger = logging.getLogger(__name__)


class PasswordPolicyServlet(RestServlet):
    PATTERNS = client_patterns("/password_policy$")

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        super().__init__()

        self.policy = hs.config.password_policy
        self.enabled = hs.config.password_policy_enabled

    def on_GET(self, request):
        if not self.enabled or not self.policy:
            return (200, {})

        policy = {}

        for param in [
            "minimum_length",
            "require_digit",
            "require_symbol",
            "require_lowercase",
            "require_uppercase",
        ]:
            if param in self.policy:
                policy["m.%s" % param] = self.policy[param]

        return (200, policy)


def register_servlets(hs, http_server):
    PasswordPolicyServlet(hs).register(http_server)
