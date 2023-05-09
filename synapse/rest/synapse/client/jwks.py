# Copyright 2022 The Matrix.org Foundation C.I.C.
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
from typing import TYPE_CHECKING, Tuple

from synapse.http.server import DirectServeJsonResource
from synapse.http.site import SynapseRequest
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class JwksResource(DirectServeJsonResource):
    def __init__(self, hs: "HomeServer"):
        super().__init__(extract_context=True)

        # Parameters that are allowed to be exposed in the public key.
        # This is done manually, because authlib's private to public key conversion
        # is unreliable depending on the version. Instead, we just serialize the private
        # key and only keep the public parameters.
        # List from https://www.iana.org/assignments/jose/jose.xhtml#web-key-parameters
        public_parameters = {
            "kty",
            "use",
            "key_ops",
            "alg",
            "kid",
            "x5u",
            "x5c",
            "x5t",
            "x5t#S256",
            "crv",
            "x",
            "y",
            "n",
            "e",
            "ext",
        }

        key = hs.config.experimental.msc3861.jwk

        if key is not None:
            private_key = key.as_dict()
            public_key = {
                k: v for k, v in private_key.items() if k in public_parameters
            }
            keys = [public_key]
        else:
            keys = []

        self.res = {
            "keys": keys,
        }

    async def _async_render_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        return 200, self.res
