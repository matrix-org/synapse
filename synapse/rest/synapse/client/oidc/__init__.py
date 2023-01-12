# Copyright 2020 Quentin Gliech
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
from typing import TYPE_CHECKING

from twisted.web.resource import Resource

from synapse.rest.synapse.client.oidc.backchannel_logout_resource import (
    OIDCBackchannelLogoutResource,
)
from synapse.rest.synapse.client.oidc.callback_resource import OIDCCallbackResource

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class OIDCResource(Resource):
    def __init__(self, hs: "HomeServer"):
        Resource.__init__(self)
        self.putChild(b"callback", OIDCCallbackResource(hs))
        self.putChild(b"backchannel_logout", OIDCBackchannelLogoutResource(hs))


__all__ = ["OIDCResource"]
