# Copyright 2020 Awesome Technologies Innovationslabor GmbH
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


from synapse.types import UserID

from tests import unittest


class DataStoreTestCase(unittest.HomeserverTestCase):
    def setUp(self) -> None:
        super(DataStoreTestCase, self).setUp()

        self.store = self.hs.get_datastores().main

        self.user = UserID.from_string("@abcde:test")
        self.displayname = "Frank"

    def test_get_users_paginate(self) -> None:
        self.get_success(self.store.register_user(self.user.to_string(), "pass"))
        self.get_success(self.store.create_profile(self.user.localpart))
        self.get_success(
            self.store.set_profile_displayname(self.user.localpart, self.displayname)
        )

        users, total = self.get_success(
            self.store.get_users_paginate(0, 10, name="bc", guests=False)
        )

        self.assertEqual(1, total)
        self.assertEqual(self.displayname, users.pop()["displayname"])

        users, total = self.get_success(
            self.store.get_users_paginate(0, 10, name="BC", guests=False)
        )

        self.assertEqual(1, total)
        self.assertEqual(self.displayname, users.pop()["displayname"])
