# Copyright 2014-2016 OpenMarket Ltd
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

from unittest.mock import Mock

import synapse.types
from synapse.api.errors import AuthError, SynapseError
from synapse.types import UserID

from tests import unittest
from tests.test_utils import make_awaitable


class ProfileTestCase(unittest.HomeserverTestCase):
    """ Tests profile management. """

    def make_homeserver(self, reactor, clock):
        self.mock_federation = Mock()
        self.mock_registry = Mock()

        self.query_handlers = {}

        def register_query_handler(query_type, handler):
            self.query_handlers[query_type] = handler

        self.mock_registry.register_query_handler = register_query_handler

        hs = self.setup_test_homeserver(
            federation_client=self.mock_federation,
            federation_server=Mock(),
            federation_registry=self.mock_registry,
        )
        return hs

    def prepare(self, reactor, clock, hs):
        self.store = hs.get_datastore()

        self.frank = UserID.from_string("@1234ABCD:test")
        self.bob = UserID.from_string("@4567:test")
        self.alice = UserID.from_string("@alice:remote")

        self.get_success(self.store.create_profile(self.frank.localpart))

        self.handler = hs.get_profile_handler()

    def test_get_my_name(self):
        self.get_success(
            self.store.set_profile_displayname(self.frank.localpart, "Frank")
        )

        displayname = self.get_success(self.handler.get_displayname(self.frank))

        self.assertEquals("Frank", displayname)

    def test_set_my_name(self):
        self.get_success(
            self.handler.set_displayname(
                self.frank, synapse.types.create_requester(self.frank), "Frank Jr."
            )
        )

        self.assertEquals(
            (
                self.get_success(
                    self.store.get_profile_displayname(self.frank.localpart)
                )
            ),
            "Frank Jr.",
        )

        # Set displayname again
        self.get_success(
            self.handler.set_displayname(
                self.frank, synapse.types.create_requester(self.frank), "Frank"
            )
        )

        self.assertEquals(
            (
                self.get_success(
                    self.store.get_profile_displayname(self.frank.localpart)
                )
            ),
            "Frank",
        )

        # Set displayname to an empty string
        self.get_success(
            self.handler.set_displayname(
                self.frank, synapse.types.create_requester(self.frank), ""
            )
        )

        self.assertIsNone(
            (self.get_success(self.store.get_profile_displayname(self.frank.localpart)))
        )

    def test_set_my_name_if_disabled(self):
        self.hs.config.enable_set_displayname = False

        # Setting displayname for the first time is allowed
        self.get_success(
            self.store.set_profile_displayname(self.frank.localpart, "Frank")
        )

        self.assertEquals(
            (
                self.get_success(
                    self.store.get_profile_displayname(self.frank.localpart)
                )
            ),
            "Frank",
        )

        # Setting displayname a second time is forbidden
        self.get_failure(
            self.handler.set_displayname(
                self.frank, synapse.types.create_requester(self.frank), "Frank Jr."
            ),
            SynapseError,
        )

    def test_set_my_name_noauth(self):
        self.get_failure(
            self.handler.set_displayname(
                self.frank, synapse.types.create_requester(self.bob), "Frank Jr."
            ),
            AuthError,
        )

    def test_get_other_name(self):
        self.mock_federation.make_query.return_value = make_awaitable(
            {"displayname": "Alice"}
        )

        displayname = self.get_success(self.handler.get_displayname(self.alice))

        self.assertEquals(displayname, "Alice")
        self.mock_federation.make_query.assert_called_with(
            destination="remote",
            query_type="profile",
            args={"user_id": "@alice:remote", "field": "displayname"},
            ignore_backoff=True,
        )

    def test_incoming_fed_query(self):
        self.get_success(self.store.create_profile("caroline"))
        self.get_success(self.store.set_profile_displayname("caroline", "Caroline"))

        response = self.get_success(
            self.query_handlers["profile"](
                {
                    "user_id": "@caroline:test",
                    "field": "displayname",
                    "origin": "servername.tld",
                }
            )
        )

        self.assertEquals({"displayname": "Caroline"}, response)

    def test_get_my_avatar(self):
        self.get_success(
            self.store.set_profile_avatar_url(
                self.frank.localpart, "http://my.server/me.png"
            )
        )
        avatar_url = self.get_success(self.handler.get_avatar_url(self.frank))

        self.assertEquals("http://my.server/me.png", avatar_url)

    def test_set_my_avatar(self):
        self.get_success(
            self.handler.set_avatar_url(
                self.frank,
                synapse.types.create_requester(self.frank),
                "http://my.server/pic.gif",
            )
        )

        self.assertEquals(
            (self.get_success(self.store.get_profile_avatar_url(self.frank.localpart))),
            "http://my.server/pic.gif",
        )

        # Set avatar again
        self.get_success(
            self.handler.set_avatar_url(
                self.frank,
                synapse.types.create_requester(self.frank),
                "http://my.server/me.png",
            )
        )

        self.assertEquals(
            (self.get_success(self.store.get_profile_avatar_url(self.frank.localpart))),
            "http://my.server/me.png",
        )

        # Set avatar to an empty string
        self.get_success(
            self.handler.set_avatar_url(
                self.frank,
                synapse.types.create_requester(self.frank),
                "",
            )
        )

        self.assertIsNone(
            (self.get_success(self.store.get_profile_avatar_url(self.frank.localpart))),
        )

    def test_set_my_avatar_if_disabled(self):
        self.hs.config.enable_set_avatar_url = False

        # Setting displayname for the first time is allowed
        self.get_success(
            self.store.set_profile_avatar_url(
                self.frank.localpart, "http://my.server/me.png"
            )
        )

        self.assertEquals(
            (self.get_success(self.store.get_profile_avatar_url(self.frank.localpart))),
            "http://my.server/me.png",
        )

        # Set avatar a second time is forbidden
        self.get_failure(
            self.handler.set_avatar_url(
                self.frank,
                synapse.types.create_requester(self.frank),
                "http://my.server/pic.gif",
            ),
            SynapseError,
        )
