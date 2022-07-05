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
from typing import TYPE_CHECKING, Tuple

from twisted.web.server import Request

from synapse.api.constants import RoomCreationPreset
from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class VersionsRestServlet(RestServlet):
    PATTERNS = [re.compile("^/_matrix/client/versions$")]

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.config = hs.config

        # Calculate these once since they shouldn't change after start-up.
        self.e2ee_forced_public = (
            RoomCreationPreset.PUBLIC_CHAT
            in self.config.room.encryption_enabled_by_default_for_room_presets
        )
        self.e2ee_forced_private = (
            RoomCreationPreset.PRIVATE_CHAT
            in self.config.room.encryption_enabled_by_default_for_room_presets
        )
        self.e2ee_forced_trusted_private = (
            RoomCreationPreset.TRUSTED_PRIVATE_CHAT
            in self.config.room.encryption_enabled_by_default_for_room_presets
        )

    def on_GET(self, request: Request) -> Tuple[int, JsonDict]:
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
                    "r0.6.1",
                    "v1.1",
                    "v1.2",
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
                    "uk.half-shot.msc2666.mutual_rooms": True,
                    # Whether new rooms will be set to encrypted or not (based on presets).
                    "io.element.e2ee_forced.public": self.e2ee_forced_public,
                    "io.element.e2ee_forced.private": self.e2ee_forced_private,
                    "io.element.e2ee_forced.trusted_private": self.e2ee_forced_trusted_private,
                    # Supports the busy presence state described in MSC3026.
                    "org.matrix.msc3026.busy_presence": self.config.experimental.msc3026_enabled,
                    # Supports receiving private read receipts as per MSC2285
                    "org.matrix.msc2285": self.config.experimental.msc2285_enabled,
                    # Supports filtering of /publicRooms by room type MSC3827
                    "org.matrix.msc3827": self.config.experimental.msc3827_enabled,
                    # Adds support for importing historical messages as per MSC2716
                    "org.matrix.msc2716": self.config.experimental.msc2716_enabled,
                    # Adds support for jump to date endpoints (/timestamp_to_event) as per MSC3030
                    "org.matrix.msc3030": self.config.experimental.msc3030_enabled,
                    # Adds support for thread relations, per MSC3440.
                    "org.matrix.msc3440.stable": True,  # TODO: remove when "v1.3" is added above
                    # Allows moderators to fetch redacted event content as described in MSC2815
                    "fi.mau.msc2815": self.config.experimental.msc2815_enabled,
                },
            },
        )


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    VersionsRestServlet(hs).register(http_server)
