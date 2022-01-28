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
from typing import Any, Dict
from unittest.mock import Mock

import synapse.types
from synapse.api.errors import AuthError, SynapseError
from synapse.rest import admin
from synapse.server import HomeServer
from synapse.types import UserID

from tests import unittest
from tests.test_utils import make_awaitable


class ProfileTestCase(unittest.HomeserverTestCase):
    """Tests profile management."""

    servlets = [admin.register_servlets]

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

    def prepare(self, reactor, clock, hs: HomeServer):
        self.store = hs.get_datastore()

        self.frank = UserID.from_string("@1234abcd:test")
        self.bob = UserID.from_string("@4567:test")
        self.alice = UserID.from_string("@alice:remote")

        self.get_success(self.register_user(self.frank.localpart, "frankpassword"))

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
            self.get_success(self.store.get_profile_displayname(self.frank.localpart))
        )

    def test_set_my_name_if_disabled(self):
        self.hs.config.registration.enable_set_displayname = False

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
        self.hs.config.registration.enable_set_avatar_url = False

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

    def test_avatar_constraints_no_config(self):
        """Tests that the method to check an avatar against configured constraints skips
        all of its check if no constraint is configured.
        """
        # The first check that's done by this method is whether the file exists; if we
        # don't get an error on a non-existing file then it means all of the checks were
        # successfully skipped.
        res = self.get_success(
            self.handler.check_avatar_size_and_mime_type("mxc://test/unknown_file")
        )
        self.assertTrue(res)

    @unittest.override_config({"max_avatar_size": 50})
    def test_avatar_constraints_missing(self):
        """Tests that an avatar isn't allowed if the file at the given MXC URI couldn't
        be found.
        """
        res = self.get_success(
            self.handler.check_avatar_size_and_mime_type("mxc://test/unknown_file")
        )
        self.assertFalse(res)

    @unittest.override_config({"max_avatar_size": 50})
    def test_avatar_constraints_file_size(self):
        """Tests that a file that's above the allowed file size is forbidden but one
        that's below it is allowed.
        """
        self._setup_local_files(
            {
                "small": {"size": 40},
                "big": {"size": 60},
            }
        )

        res = self.get_success(
            self.handler.check_avatar_size_and_mime_type("mxc://test/small")
        )
        self.assertTrue(res)

        res = self.get_success(
            self.handler.check_avatar_size_and_mime_type("mxc://test/big")
        )
        self.assertFalse(res)

    @unittest.override_config({"allowed_avatar_mimetypes": ["image/png"]})
    def test_avatar_constraint_mime_type(self):
        """Tests that a file with an unauthorised MIME type is forbidden but one with
        an authorised content type is allowed.
        """
        self._setup_local_files(
            {
                "good": {"mimetype": "image/png"},
                "bad": {"mimetype": "application/octet-stream"},
            }
        )

        res = self.get_success(
            self.handler.check_avatar_size_and_mime_type("mxc://test/good")
        )
        self.assertTrue(res)

        res = self.get_success(
            self.handler.check_avatar_size_and_mime_type("mxc://test/bad")
        )
        self.assertFalse(res)

    def _setup_local_files(self, names_and_props: Dict[str, Dict[str, Any]]):
        """Stores metadata about files in the database.

        Args:
            names_and_props: A dictionary with one entry per file, with the key being the
                file's name, and the value being a dictionary of properties. Supported
                properties are "mimetype" (for the file's type) and "size" (for the
                file's size).
        """
        store = self.hs.get_datastore()

        for name, props in names_and_props.items():
            self.get_success(
                store.store_local_media(
                    media_id=name,
                    media_type=props.get("mimetype", "image/png"),
                    time_now_ms=self.clock.time_msec(),
                    upload_name=None,
                    media_length=props.get("size", 50),
                    user_id=UserID.from_string("@rin:test"),
                )
            )
