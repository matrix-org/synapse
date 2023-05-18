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
from twisted.test.proto_helpers import MemoryReactor

from synapse.api.errors import SynapseError
from synapse.rest import admin
from synapse.server import HomeServer
from synapse.util import Clock

from tests.unittest import HomeserverTestCase


class ModuleApiTestCase(HomeserverTestCase):
    servlets = [
        admin.register_servlets,
    ]

    def prepare(
        self, reactor: MemoryReactor, clock: Clock, homeserver: HomeServer
    ) -> None:
        self._store = homeserver.get_datastores().main
        self._module_api = homeserver.get_module_api()
        self._account_data_mgr = self._module_api.account_data_manager

        self.user_id = self.register_user("kristina", "secret")

    def test_get_global(self) -> None:
        """
        Tests that getting global account data through the module API works as
        expected, including getting `None` for unset account data.
        """
        self.get_success(
            self._store.add_account_data_for_user(
                self.user_id, "test.data", {"wombat": True}
            )
        )

        # Getting existent account data works as expected.
        self.assertEqual(
            self.get_success(
                self._account_data_mgr.get_global(self.user_id, "test.data")
            ),
            {"wombat": True},
        )

        # Getting non-existent account data returns None.
        self.assertIsNone(
            self.get_success(
                self._account_data_mgr.get_global(self.user_id, "no.data.at.all")
            )
        )

    def test_get_global_validation(self) -> None:
        """
        Tests that invalid or remote user IDs are treated as errors and raised as exceptions,
        whilst getting global account data for a user.

        This is a design choice to try and communicate potential bugs to modules
        earlier on.
        """
        with self.assertRaises(SynapseError):
            self.get_success_or_raise(
                self._account_data_mgr.get_global("this isn't a user id", "test.data")
            )

        with self.assertRaises(ValueError):
            self.get_success_or_raise(
                self._account_data_mgr.get_global("@valid.but:remote", "test.data")
            )

    def test_get_global_no_mutability(self) -> None:
        """
        Tests that modules can't introduce bugs into Synapse by mutating the result
        of `get_global`.
        """
        # First add some account data to set up the test.
        self.get_success(
            self._store.add_account_data_for_user(
                self.user_id, "test.data", {"wombat": True}
            )
        )

        # Now request that data and then mutate it (out of negligence or otherwise).
        the_data = self.get_success(
            self._account_data_mgr.get_global(self.user_id, "test.data")
        )
        with self.assertRaises(TypeError):
            # This throws an exception because it's a frozen dict.
            the_data["wombat"] = False  # type: ignore[index]

    def test_put_global(self) -> None:
        """
        Tests that written account data using `put_global` can be read out again later.
        """

        self.get_success(
            self._module_api.account_data_manager.put_global(
                self.user_id, "test.data", {"wombat": True}
            )
        )

        # Request that account data from the normal store; check it's as we expect.
        self.assertEqual(
            self.get_success(
                self._store.get_global_account_data_by_type_for_user(
                    self.user_id, "test.data"
                )
            ),
            {"wombat": True},
        )

    def test_put_global_validation(self) -> None:
        """
        Tests that a module can't write account data to user IDs that don't have
        actual users registered to them.
        Modules also must supply the correct types.
        """

        with self.assertRaises(SynapseError):
            self.get_success_or_raise(
                self._account_data_mgr.put_global(
                    "this isn't a user id", "test.data", {}
                )
            )

        with self.assertRaises(ValueError):
            self.get_success_or_raise(
                self._account_data_mgr.put_global("@valid.but:remote", "test.data", {})
            )

        with self.assertRaises(ValueError):
            self.get_success_or_raise(
                self._module_api.account_data_manager.put_global(
                    "@notregistered:test", "test.data", {}
                )
            )

        with self.assertRaises(TypeError):
            # The account data type must be a string.
            self.get_success_or_raise(
                self._module_api.account_data_manager.put_global(self.user_id, 42, {})  # type: ignore[arg-type]
            )

        with self.assertRaises(TypeError):
            # The account data dict must be a dict.
            # noinspection PyTypeChecker
            self.get_success_or_raise(
                self._module_api.account_data_manager.put_global(
                    self.user_id, "test.data", 42  # type: ignore[arg-type]
                )
            )
