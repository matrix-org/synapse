# Copyright 2023 The Matrix.org Foundation C.I.C.
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
from OpenSSL.SSL import Context
from twisted.internet import ssl

from synapse.config.redis import RedisConfig


class ClientContextFactory(ssl.ClientContextFactory):
    def __init__(self, redis_config: RedisConfig):
        self.redis_config = redis_config

    def getContext(self) -> Context:
        ctx = super().getContext()
        if self.redis_config.redis_certificate:
            ctx.use_certificate_file(self.redis_config.redis_certificate)
        if self.redis_config.redis_private_key:
            ctx.use_privatekey_file(self.redis_config.redis_private_key)
        if self.redis_config.redis_ca_file:
            ctx.load_verify_locations(cafile=self.redis_config.redis_ca_file)
        elif self.redis_config.redis_ca_path:
            ctx.load_verify_locations(capath=self.redis_config.redis_ca_path)
        return ctx
