# Copyright 2014 - 2016 OpenMarket Ltd
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
from typing import TYPE_CHECKING, Optional

from synapse.api.ratelimiting import Ratelimiter
from synapse.types import Requester

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class BaseHandler:
    """
    Common base class for the event handlers.

    Deprecated: new code should not use this. Instead, Handler classes should define the
    fields they actually need. The utility methods should either be factored out to
    standalone helper functions, or to different Handler classes.
    """

    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastore()
        self.auth = hs.get_auth()
        self.distributor = hs.get_distributor()
        self.clock = hs.get_clock()
        self.hs = hs
        self.server_name = hs.hostname
