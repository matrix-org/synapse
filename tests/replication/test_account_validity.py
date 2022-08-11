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
from typing import Optional, cast

from twisted.internet.defer import ensureDeferred

import synapse
from synapse.module_api import DatabasePool, LoggingTransaction, ModuleApi, cached
from synapse.server import HomeServer

from tests.replication._base import BaseMultiWorkerStreamTestCase
from tests.server import ThreadedMemoryReactorClock, make_request

logger = logging.getLogger(__name__)


class MockAccountValidityStore:
    def __init__(
        self,
        api: ModuleApi,
    ):
        self._api = api

        api.register_cached_function(self.is_user_expired)

    async def create_db(self):
        def create_table_txn(txn: LoggingTransaction):
            txn.execute(
                """
                CREATE TABLE IF NOT EXISTS mock_account_validity(
                    user_id TEXT PRIMARY KEY,
                    expired BOOLEAN NOT NULL
                )
                """,
                (),
            )

        await self._api.run_db_interaction(
            "account_validity_create_table",
            create_table_txn,
        )

    @cached()
    async def is_user_expired(self, user_id: str) -> Optional[bool]:
        def get_expiration_for_user_txn(txn: LoggingTransaction):
            return DatabasePool.simple_select_one_onecol_txn(
                txn=txn,
                table="mock_account_validity",
                keyvalues={"user_id": user_id},
                retcol="expired",
                allow_none=True,
            )

        return await self._api.run_db_interaction(
            "get_expiration_for_user",
            get_expiration_for_user_txn,
        )

    async def on_user_registration(self, user_id: str) -> None:
        def add_valid_user_txn(txn: LoggingTransaction):
            txn.execute(
                "INSERT INTO mock_account_validity (user_id, expired) VALUES (?, ?)",
                (user_id, False),
            )

        await self._api.run_db_interaction(
            "account_validity_add_valid_user",
            add_valid_user_txn,
        )

    async def set_expired(self, user_id: str, expired: bool = True) -> None:
        def set_expired_user_txn(txn: LoggingTransaction):
            txn.execute(
                "UPDATE mock_account_validity SET expired = ? WHERE user_id = ?",
                (
                    expired,
                    user_id,
                ),
            )

        await self._api.run_db_interaction(
            "account_validity_set_expired_user",
            set_expired_user_txn,
        )

        await self._api.invalidate_cache(self.is_user_expired, (user_id,))


class MockAccountValidity:
    def __init__(
        self,
        config,
        api: ModuleApi,
    ):
        self._api = api

        self._store = MockAccountValidityStore(api)

        ensureDeferred(self._store.create_db())
        cast(ThreadedMemoryReactorClock, api._hs.get_reactor()).pump([0.0])

        self._api.register_account_validity_callbacks(
            is_user_expired=self.is_user_expired,
            on_user_registration=self.on_user_registration,
        )

    async def is_user_expired(self, user_id: str) -> Optional[bool]:
        return await self._store.is_user_expired(user_id)

    async def on_user_registration(self, user_id: str) -> None:
        await self._store.on_user_registration(user_id)


class WorkerAccountValidityTestCase(BaseMultiWorkerStreamTestCase):
    servlets = [
        synapse.rest.admin.register_servlets,
        synapse.rest.client.account.register_servlets,
        synapse.rest.client.login.register_servlets,
        synapse.rest.client.register.register_servlets,
    ]

    def default_config(self):
        config = super().default_config()

        config["modules"] = [
            {
                "module": __name__ + ".MockAccountValidity",
            }
        ]

        return config

    def make_homeserver(self, reactor, clock):
        hs = super().make_homeserver(reactor, clock)
        module_api = hs.get_module_api()
        for module, config in hs.config.modules.loaded_modules:
            self.module = module(config=config, api=module_api)
            logger.info("Loaded module %s", self.module)
        return hs

    def make_worker_hs(
        self, worker_app: str, extra_config: Optional[dict] = None, **kwargs
    ) -> HomeServer:
        hs = super().make_worker_hs(worker_app, extra_config=extra_config)
        module_api = hs.get_module_api()
        for module, config in hs.config.modules.loaded_modules:
            # Do not store the module in self here since we want to expire the user
            # from the main worker and see if it get properly replicated to the other one.
            module(config=config, api=module_api)
            logger.info("Loaded module %s", self.module)
        return hs

    def _create_and_check_user(self):
        self.register_user("user", "pass")
        user_id = "@user:test"
        token = self.login("user", "pass")

        channel = self.make_request(
            "GET",
            "/_matrix/client/v3/account/whoami",
            access_token=token,
        )

        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.json_body["user_id"], user_id)

        return user_id, token

    def test_account_validity(self):
        user_id, token = self._create_and_check_user()

        self.get_success_or_raise(self.module._store.set_expired(user_id))

        channel = self.make_request(
            "GET",
            "/_matrix/client/v3/account/whoami",
            access_token=token,
        )
        self.assertEqual(channel.code, 403)

        self.get_success_or_raise(self.module._store.set_expired(user_id, False))

        channel = self.make_request(
            "GET",
            "/_matrix/client/v3/account/whoami",
            access_token=token,
        )
        self.assertEqual(channel.code, 200)

    def test_account_validity_with_worker_and_cache(self):
        worker_hs = self.make_worker_hs("synapse.app.generic_worker")
        worker_site = self._hs_to_site[worker_hs]

        user_id, token = self._create_and_check_user()

        # check than the user is valid on the other worker too
        channel = make_request(
            self.reactor,
            worker_site,
            "GET",
            "/_matrix/client/v3/account/whoami",
            access_token=token,
        )
        self.assertEqual(channel.code, 200)

        # Expires user on the main worker, and check its state on the other worker
        self.get_success_or_raise(self.module._store.set_expired(user_id))

        channel = make_request(
            self.reactor,
            worker_site,
            "GET",
            "/_matrix/client/v3/account/whoami",
            access_token=token,
        )
        self.assertEqual(channel.code, 403)

        # Un-expires user on the main worker, and check its state on the other worker
        self.get_success_or_raise(self.module._store.set_expired(user_id, False))

        channel = make_request(
            self.reactor,
            worker_site,
            "GET",
            "/_matrix/client/v3/account/whoami",
            access_token=token,
        )
        self.assertEqual(channel.code, 200)
