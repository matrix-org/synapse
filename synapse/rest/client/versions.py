# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
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

from synapse.http.servlet import RestServlet

logger = logging.getLogger(__name__)


class VersionsRestServlet(RestServlet):
    PATTERNS = [re.compile("^/_matrix/client/versions$")]

    def on_GET(self, request):
        return (
            200,
            {
                "versions": [
                    # XXX: at some point we need to decide whether we need to include
                    # the previous version numbers, given we've defined r0.3.0 to be
                    # backwards compatible with r0.2.0.  But need to check how
                    # conscientious we've been in compatibility, and decide whether the
                    # middle number is the major revision when at 0.X.Y (as opposed to
                    # X.Y.Z).  And we need to decide whether it's fair to make clients
                    # parse the version string to figure out what's going on.
                    "r0.0.1",
                    "r0.1.0",
                    "r0.2.0",
                    "r0.3.0",
                    "r0.4.0",
                    "r0.5.0",
                ],
                # as per MSC1497:
                "unstable_features": {"m.lazy_load_members": True},
            },
        )


def register_servlets(http_server):
    VersionsRestServlet().register(http_server)
