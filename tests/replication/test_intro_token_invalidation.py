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
