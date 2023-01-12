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
from typing import Any, Awaitable, Callable, Dict
from unittest.mock import Mock

from parameterized import parameterized

from twisted.test.proto_helpers import MemoryReactor

import synapse.types
from synapse.api.errors import AuthError, SynapseError
from synapse.rest import admin
from synapse.server import HomeServer
from synapse.types import JsonDict, UserID
from synapse.util import Clock

from tests import unittest
from tests.test_utils import make_awaitable


class ProfileTestCase(unittest.HomeserverTestCase):
    """Tests profile management."""

    servlets = [admin.register_servlets]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        self.mock_federation = Mock()
        self.mock_registry = Mock()

        self.query_handlers: Dict[str, Callable[[dict], Awaitable[JsonDict]]] = {}

        def register_query_handler(
            query_type: str, handler: Callable[[dict], Awaitable[JsonDict]]
        ) -> None:
            self.query_handlers[query_type] = handler

        self.mock_registry.register_query_handler = register_query_handler

        hs = self.setup_test_homeserver(
            federation_client=self.mock_federation,
            federation_server=Mock(),
            federation_registry=self.mock_registry,
        )
        return hs

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main

        self.frank = UserID.from_string("@1234abcd:test")
        self.bob = UserID.from_string("@4567:test")
        self.alice = UserID.from_string("@alice:remote")

        self.register_user(self.frank.localpart, "frankpassword")

        self.handler = hs.get_profile_handler()

    def test_get_my_name(self) -> None:
        self.get_success(
            self.store.set_profile_displayname(self.frank.localpart, "Frank")
        )

        displayname = self.get_success(self.handler.get_displayname(self.frank))

        self.assertEqual("Frank", displayname)

    def test_set_my_name(self) -> None:
        self.get_success(
            self.handler.set_displayname(
                self.frank, synapse.types.create_requester(self.frank), "Frank Jr."
            )
        )

        self.assertEqual(
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

        self.assertEqual(
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

    def test_set_my_name_if_disabled(self) -> None:
        self.hs.config.registration.enable_set_displayname = False

        # Setting displayname for the first time is allowed
        self.get_success(
            self.store.set_profile_displayname(self.frank.localpart, "Frank")
        )

        self.assertEqual(
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

    def test_set_my_name_noauth(self) -> None:
        self.get_failure(
            self.handler.set_displayname(
                self.frank, synapse.types.create_requester(self.bob), "Frank Jr."
            ),
            AuthError,
        )

    def test_get_other_name(self) -> None:
        self.mock_federation.make_query.return_value = make_awaitable(
            {"displayname": "Alice"}
        )

        displayname = self.get_success(self.handler.get_displayname(self.alice))

        self.assertEqual(displayname, "Alice")
        self.mock_federation.make_query.assert_called_with(
            destination="remote",
            query_type="profile",
            args={"user_id": "@alice:remote", "field": "displayname"},
            ignore_backoff=True,
        )

    def test_incoming_fed_query(self) -> None:
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

        self.assertEqual({"displayname": "Caroline"}, response)

    def test_get_my_avatar(self) -> None:
        self.get_success(
            self.store.set_profile_avatar_url(
                self.frank.localpart, "http://my.server/me.png"
            )
        )
        avatar_url = self.get_success(self.handler.get_avatar_url(self.frank))

        self.assertEqual("http://my.server/me.png", avatar_url)

    def test_set_my_avatar(self) -> None:
        self.get_success(
            self.handler.set_avatar_url(
                self.frank,
                synapse.types.create_requester(self.frank),
                "http://my.server/pic.gif",
            )
        )

        self.assertEqual(
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

        self.assertEqual(
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

    def test_set_my_avatar_if_disabled(self) -> None:
        self.hs.config.registration.enable_set_avatar_url = False

        # Setting displayname for the first time is allowed
        self.get_success(
            self.store.set_profile_avatar_url(
                self.frank.localpart, "http://my.server/me.png"
            )
        )

        self.assertEqual(
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

    def test_avatar_constraints_no_config(self) -> None:
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
    def test_avatar_constraints_allow_empty_avatar_url(self) -> None:
        """An empty avatar is always permitted."""
        res = self.get_success(self.handler.check_avatar_size_and_mime_type(""))
        self.assertTrue(res)

    @unittest.override_config({"max_avatar_size": 50})
    def test_avatar_constraints_missing(self) -> None:
        """Tests that an avatar isn't allowed if the file at the given MXC URI couldn't
        be found.
        """
        res = self.get_success(
            self.handler.check_avatar_size_and_mime_type("mxc://test/unknown_file")
        )
        self.assertFalse(res)

    @unittest.override_config({"max_avatar_size": 50})
    def test_avatar_constraints_file_size(self) -> None:
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
    def test_avatar_constraint_mime_type(self) -> None:
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

    @unittest.override_config(
        {"server_name": "test:8888", "allowed_avatar_mimetypes": ["image/png"]}
    )
    def test_avatar_constraint_on_local_server_with_port(self):
        """Test that avatar metadata is correctly fetched when the media is on a local
        server and the server has an explicit port.

        (This was previously a bug)
        """
        local_server_name = self.hs.config.server.server_name
        media_id = "local"
        local_mxc = f"mxc://{local_server_name}/{media_id}"

        # mock up the existence of the avatar file
        self._setup_local_files({media_id: {"mimetype": "image/png"}})

        # and now check that check_avatar_size_and_mime_type is happy
        self.assertTrue(
            self.get_success(self.handler.check_avatar_size_and_mime_type(local_mxc))
        )

    @parameterized.expand([("remote",), ("remote:1234",)])
    @unittest.override_config({"allowed_avatar_mimetypes": ["image/png"]})
    def test_check_avatar_on_remote_server(self, remote_server_name: str) -> None:
        """Test that avatar metadata is correctly fetched from a remote server"""
        media_id = "remote"
        remote_mxc = f"mxc://{remote_server_name}/{media_id}"

        # if the media is remote, check_avatar_size_and_mime_type just checks the
        # media cache, so we don't need to instantiate a real remote server. It is
        # sufficient to poke an entry into the db.
        self.get_success(
            self.hs.get_datastores().main.store_cached_remote_media(
                media_id=media_id,
                media_type="image/png",
                media_length=50,
                origin=remote_server_name,
                time_now_ms=self.clock.time_msec(),
                upload_name=None,
                filesystem_id="xyz",
            )
        )

        self.assertTrue(
            self.get_success(self.handler.check_avatar_size_and_mime_type(remote_mxc))
        )

    def _setup_local_files(self, names_and_props: Dict[str, Dict[str, Any]]):
        """Stores metadata about files in the database.

        Args:
            names_and_props: A dictionary with one entry per file, with the key being the
                file's name, and the value being a dictionary of properties. Supported
                properties are "mimetype" (for the file's type) and "size" (for the
                file's size).
        """
        store = self.hs.get_datastores().main

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
