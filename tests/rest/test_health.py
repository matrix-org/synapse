# Copyright 2020 The Matrix.org Foundation C.I.C.
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


from synapse.rest.health import HealthResource

from tests import unittest


class HealthCheckTests(unittest.HomeserverTestCase):
    def create_test_resource(self):
        # replace the JsonResource with a HealthResource.
        return HealthResource()

    def test_health(self):
        channel = self.make_request("GET", "/health", shorthand=False)

        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.result["body"], b"OK")
