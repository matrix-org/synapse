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


from twisted.internet import defer

from synapse.types import UserID

from tests import unittest
from tests.utils import setup_test_homeserver


class DataStoreTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        hs = yield setup_test_homeserver(self.addCleanup)

        self.store = hs.get_datastore()

        self.user = UserID.from_string("@abcde:test")
        self.displayname = "Frank"

    @defer.inlineCallbacks
    def test_get_users_paginate(self):
        yield defer.ensureDeferred(
            self.store.register_user(self.user.to_string(), "pass")
        )
        yield defer.ensureDeferred(self.store.create_profile(self.user.localpart))
        yield defer.ensureDeferred(
            self.store.set_profile_displayname(self.user.localpart, self.displayname)
        )

        users, total = yield defer.ensureDeferred(
            self.store.get_users_paginate(0, 10, name="bc", guests=False)
        )

        self.assertEquals(1, total)
        self.assertEquals(self.displayname, users.pop()["displayname"])

        users, total = yield defer.ensureDeferred(
            self.store.get_users_paginate(0, 10, name="BC", guests=False)
        )

        self.assertEquals(1, total)
        self.assertEquals(self.displayname, users.pop()["displayname"])
