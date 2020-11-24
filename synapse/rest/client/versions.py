# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
# Copyright 2017 Vector Creations Ltd
# Copyright 2018-2019 New Vector Ltd
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
import re

from synapse.api.constants import RoomCreationPreset
from synapse.http.servlet import RestServlet

logger = logging.getLogger(__name__)


class VersionsRestServlet(RestServlet):
    PATTERNS = [re.compile("^/_matrix/client/versions$")]

    def __init__(self, hs):
        super().__init__()
        self.config = hs.config

        # Calculate these once since they shouldn't change after start-up.
        self.e2ee_forced_public = (
            RoomCreationPreset.PUBLIC_CHAT
            in self.config.encryption_enabled_by_default_for_room_presets
        )
        self.e2ee_forced_private = (
            RoomCreationPreset.PRIVATE_CHAT
            in self.config.encryption_enabled_by_default_for_room_presets
        )
        self.e2ee_forced_trusted_private = (
            RoomCreationPreset.TRUSTED_PRIVATE_CHAT
            in self.config.encryption_enabled_by_default_for_room_presets
        )

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
                    "r0.6.0",
                ],
                # as per MSC1497:
                "unstable_features": {
                    # Implements support for label-based filtering as described in
                    # MSC2326.
                    "org.matrix.label_based_filtering": True,
                    # Implements support for cross signing as described in MSC1756
                    "org.matrix.e2e_cross_signing": True,
                    # Implements additional endpoints as described in MSC2432
                    "org.matrix.msc2432": True,
                    # Implements additional endpoints as described in MSC2666
                    "uk.half-shot.msc2666": True,
                    # Whether new rooms will be set to encrypted or not (based on presets).
                    "io.element.e2ee_forced.public": self.e2ee_forced_public,
                    "io.element.e2ee_forced.private": self.e2ee_forced_private,
                    "io.element.e2ee_forced.trusted_private": self.e2ee_forced_trusted_private,
                },
            },
        )


def register_servlets(hs, http_server):
    VersionsRestServlet(hs).register(http_server)
