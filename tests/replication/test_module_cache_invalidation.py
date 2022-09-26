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

import synapse
from synapse.module_api import cached

from tests.replication._base import BaseMultiWorkerStreamTestCase

logger = logging.getLogger(__name__)

FIRST_VALUE = "one"
SECOND_VALUE = "two"

KEY = "mykey"


class TestCache:
    current_value = FIRST_VALUE

    @cached()
    async def cached_function(self, user_id: str) -> str:
        return self.current_value


class ModuleCacheInvalidationTestCase(BaseMultiWorkerStreamTestCase):
    servlets = [
        synapse.rest.admin.register_servlets,
    ]

    def test_module_cache_full_invalidation(self):
        main_cache = TestCache()
        self.hs.get_module_api().register_cached_function(main_cache.cached_function)

        worker_hs = self.make_worker_hs("synapse.app.generic_worker")

        worker_cache = TestCache()
        worker_hs.get_module_api().register_cached_function(
            worker_cache.cached_function
        )

        self.assertEqual(FIRST_VALUE, self.get_success(main_cache.cached_function(KEY)))
        self.assertEqual(
            FIRST_VALUE, self.get_success(worker_cache.cached_function(KEY))
        )

        main_cache.current_value = SECOND_VALUE
        worker_cache.current_value = SECOND_VALUE
        # No invalidation yet, should return the cached value on both the main process and the worker
        self.assertEqual(FIRST_VALUE, self.get_success(main_cache.cached_function(KEY)))
        self.assertEqual(
            FIRST_VALUE, self.get_success(worker_cache.cached_function(KEY))
        )

        # Full invalidation on the main process, should be replicated on the worker that
        # should returned the updated value too
        self.get_success(
            self.hs.get_module_api().invalidate_cache(
                main_cache.cached_function, (KEY,)
            )
        )

        self.assertEqual(
            SECOND_VALUE, self.get_success(main_cache.cached_function(KEY))
        )
        self.assertEqual(
            SECOND_VALUE, self.get_success(worker_cache.cached_function(KEY))
        )
