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

from typing import Any, Dict

import synapse.rest.admin._base

from tests.replication._base import BaseMultiWorkerStreamTestCase


class IntrospectionTokenCacheInvalidationTestCase(BaseMultiWorkerStreamTestCase):
    servlets = [synapse.rest.admin.register_servlets]

    def default_config(self) -> Dict[str, Any]:
        config = super().default_config()
        config["disable_registration"] = True
        config["experimental_features"] = {
            "msc3861": {
                "enabled": True,
                "issuer": "some_dude",
                "client_id": "ID",
                "client_auth_method": "client_secret_post",
                "client_secret": "secret",
            }
        }
        return config

    def test_stream_introspection_token_invalidation(self) -> None:
        worker_hs = self.make_worker_hs("synapse.app.generic_worker")
        auth = worker_hs.get_auth()
        store = self.hs.get_datastores().main

        # add a token to the cache on the worker
        auth._token_cache["open_sesame"] = "intro_token"  # type: ignore[attr-defined]

        # stream the invalidation from the master
        self.get_success(
            store.stream_introspection_token_invalidation(("open_sesame",))
        )

        # check that the cache on the worker was invalidated
        self.assertEqual(auth._token_cache.get("open_sesame"), None)  # type: ignore[attr-defined]

        # test invalidating whole cache
        for i in range(0, 5):
            auth._token_cache[f"open_sesame_{i}"] = f"intro_token_{i}"  # type: ignore[attr-defined]
        self.assertEqual(len(auth._token_cache), 5)  # type: ignore[attr-defined]

        self.get_success(store.stream_introspection_token_invalidation((None,)))

        self.assertEqual(len(auth._token_cache), 0)  # type: ignore[attr-defined]
