# Copyright 2021 The Matrix.org Foundation C.I.C.
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

from typing import Iterable, Optional, Set

from twisted.test.proto_helpers import MemoryReactor

from synapse.api.constants import AccountDataTypes
from synapse.server import HomeServer
from synapse.util import Clock

from tests import unittest


class IgnoredUsersTestCase(unittest.HomeserverTestCase):
    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = self.hs.get_datastores().main
        self.user = "@user:test"

    def _update_ignore_list(
        self, *ignored_user_ids: Iterable[str], ignorer_user_id: Optional[str] = None
    ) -> None:
        """Update the account data to block the given users."""
        if ignorer_user_id is None:
            ignorer_user_id = self.user

        self.get_success(
            self.store.add_account_data_for_user(
                ignorer_user_id,
                AccountDataTypes.IGNORED_USER_LIST,
                {"ignored_users": {u: {} for u in ignored_user_ids}},
            )
        )

    def assert_ignorers(
        self, ignored_user_id: str, expected_ignorer_user_ids: Set[str]
    ) -> None:
        self.assertEqual(
            self.get_success(self.store.ignored_by(ignored_user_id)),
            expected_ignorer_user_ids,
        )

    def assert_ignored(
        self, ignorer_user_id: str, expected_ignored_user_ids: Set[str]
    ) -> None:
        self.assertEqual(
            self.get_success(self.store.ignored_users(ignorer_user_id)),
            expected_ignored_user_ids,
        )

    def test_ignoring_users(self) -> None:
        """Basic adding/removing of users from the ignore list."""
        self._update_ignore_list("@other:test", "@another:remote")
        self.assert_ignored(self.user, {"@other:test", "@another:remote"})

        # Check a user which no one ignores.
        self.assert_ignorers("@user:test", set())

        # Check a local user which is ignored.
        self.assert_ignorers("@other:test", {self.user})

        # Check a remote user which is ignored.
        self.assert_ignorers("@another:remote", {self.user})

        # Add one user, remove one user, and leave one user.
        self._update_ignore_list("@foo:test", "@another:remote")
        self.assert_ignored(self.user, {"@foo:test", "@another:remote"})

        # Check the removed user.
        self.assert_ignorers("@other:test", set())

        # Check the added user.
        self.assert_ignorers("@foo:test", {self.user})

        # Check the removed user.
        self.assert_ignorers("@another:remote", {self.user})

    def test_caching(self) -> None:
        """Ensure that caching works properly between different users."""
        # The first user ignores a user.
        self._update_ignore_list("@other:test")
        self.assert_ignored(self.user, {"@other:test"})
        self.assert_ignorers("@other:test", {self.user})

        # The second user ignores them.
        self._update_ignore_list("@other:test", ignorer_user_id="@second:test")
        self.assert_ignored("@second:test", {"@other:test"})
        self.assert_ignorers("@other:test", {self.user, "@second:test"})

        # The first user un-ignores them.
        self._update_ignore_list()
        self.assert_ignored(self.user, set())
        self.assert_ignorers("@other:test", {"@second:test"})

    def test_invalid_data(self) -> None:
        """Invalid data ends up clearing out the ignored users list."""
        # Add some data and ensure it is there.
        self._update_ignore_list("@other:test")
        self.assert_ignored(self.user, {"@other:test"})
        self.assert_ignorers("@other:test", {self.user})

        # No ignored_users key.
        self.get_success(
            self.store.add_account_data_for_user(
                self.user,
                AccountDataTypes.IGNORED_USER_LIST,
                {},
            )
        )

        # No one ignores the user now.
        self.assert_ignored(self.user, set())
        self.assert_ignorers("@other:test", set())

        # Add some data and ensure it is there.
        self._update_ignore_list("@other:test")
        self.assert_ignored(self.user, {"@other:test"})
        self.assert_ignorers("@other:test", {self.user})

        # Invalid data.
        self.get_success(
            self.store.add_account_data_for_user(
                self.user,
                AccountDataTypes.IGNORED_USER_LIST,
                {"ignored_users": "unexpected"},
            )
        )

        # No one ignores the user now.
        self.assert_ignored(self.user, set())
        self.assert_ignorers("@other:test", set())

    def test_ignoring_users_with_latest_stream_ids(self) -> None:
        """Test that ignoring users updates the latest stream ID for the ignored
        user list account data."""

        def get_latest_ignore_streampos(user_id: str) -> Optional[int]:
            return self.get_success(
                self.store.get_latest_stream_id_for_global_account_data_by_type_for_user(
                    user_id, AccountDataTypes.IGNORED_USER_LIST
                )
            )

        self.assertIsNone(get_latest_ignore_streampos("@user:test"))

        self._update_ignore_list("@other:test", "@another:remote")

        self.assertEqual(get_latest_ignore_streampos("@user:test"), 2)

        # Add one user, remove one user, and leave one user.
        self._update_ignore_list("@foo:test", "@another:remote")

        self.assertEqual(get_latest_ignore_streampos("@user:test"), 3)
