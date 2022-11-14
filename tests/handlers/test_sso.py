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
from http import HTTPStatus
from typing import BinaryIO, Callable, Dict, List, Optional, Tuple
from unittest.mock import Mock

from twisted.test.proto_helpers import MemoryReactor
from twisted.web.http_headers import Headers

from synapse.api.errors import Codes, SynapseError
from synapse.http.client import RawHeaders
from synapse.server import HomeServer
from synapse.util import Clock

from tests import unittest
from tests.test_utils import SMALL_PNG, FakeResponse


class TestSSOHandler(unittest.HomeserverTestCase):
    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        self.http_client = Mock(spec=["get_file"])
        self.http_client.get_file.side_effect = mock_get_file
        self.http_client.user_agent = b"Synapse Test"
        hs = self.setup_test_homeserver(proxied_blacklisted_http_client=self.http_client)
        return hs

    async def test_set_avatar(self) -> None:
        """Tests successfully setting the avatar of a newly created user"""
        handler = self.hs.get_sso_handler()

        # Create a new user to set avatar for
        reg_handler = self.hs.get_registration_handler()
        user_id = self.get_success(reg_handler.register_user(approved=True))

        with self.assertLogs() as cm:
            self.get_success(handler.set_avatar(user_id, "http://my.server/me.png"))
        self.assertEqual(
            cm.output[-1],
            "INFO:synapse.handlers.sso:successfully saved the user avatar",
        )

        # Ensure avatar is set on this newly created user,
        # so no need to compare for the exact image
        profile_handler = self.hs.get_profile_handler()
        profile = self.get_success(profile_handler.get_profile(user_id))
        self.assertIsNot(profile["avatar_url"], None)

    @unittest.override_config({"max_avatar_size": 65})
    async def test_set_avatar_too_big_image(self) -> None:
        """Tests saving of avatar failed when image size is too big"""
        handler = self.hs.get_sso_handler()

        # any random user works since image check is supposed to fail
        user_id = "@sso-user:test"

        with self.assertLogs() as cm:
            self.get_success(handler.set_avatar(user_id, "http://my.server/me.png"))
        self.assertEqual(
            cm.output, ["WARNING:synapse.handlers.sso:failed to save the user avatar"]
        )

    @unittest.override_config({"allowed_avatar_mimetypes": ["image/jpeg"]})
    async def test_set_avatar_incorrect_mime_type(self) -> None:
        """Tests saving of avatar failed when not allowed mimetype of image was used"""
        handler = self.hs.get_sso_handler()

        # any random user works since image check is supposed to fail
        user_id = "@sso-user:test"

        with self.assertLogs() as cm:
            self.get_success(handler.set_avatar(user_id, "http://my.server/me.png"))
        self.assertEqual(
            cm.output, ["WARNING:synapse.handlers.sso:failed to save the user avatar"]
        )

    async def test_skip_saving_avatar_when_not_changed(self) -> None:
        """Tests whether saving of avatar correctly skips if the avatar hasn't changed"""
        handler = self.hs.get_sso_handler()

        # Create a new user to set avatar for
        reg_handler = self.hs.get_registration_handler()
        user_id = self.get_success(reg_handler.register_user(approved=True))

        with self.assertLogs() as cm:
            self.get_success(handler.set_avatar(user_id, "http://my.server/me.png"))
        self.assertEqual(
            cm.output[-1],
            "INFO:synapse.handlers.sso:successfully saved the user avatar",
        )

        with self.assertLogs() as cm:
            self.get_success(handler.set_avatar(user_id, "http://my.server/me.png"))
        self.assertEqual(
            cm.output[-1],
            "INFO:synapse.handlers.sso:skipping saving the user avatar",
        )


async def mock_get_file(
    url: str,
    output_stream: BinaryIO,
    max_size: Optional[int] = None,
    headers: Optional[RawHeaders] = None,
    is_allowed_content_type: Optional[Callable[[str], bool]] = None,
) -> Tuple[int, Dict[bytes, List[bytes]], str, int]:

    fake_response = FakeResponse(code=404)
    if url == "http://my.server/me.png":
        fake_response = FakeResponse(
            code=200,
            headers=Headers({"Content-Type": ["image/png"], "Content-Length": ["67"]}),
            body=SMALL_PNG,
        )

    if max_size is not None and max_size < 67:
        raise SynapseError(
            HTTPStatus.BAD_GATEWAY,
            "Requested file is too large > %r bytes" % (max_size,),
            Codes.TOO_LARGE,
        )

    if is_allowed_content_type and not is_allowed_content_type("image/png"):
        raise SynapseError(
            HTTPStatus.BAD_GATEWAY,
            (
                "Requested file's content type not allowed for this operation: %s"
                % "image/png"
            ),
        )

    output_stream.write(fake_response.body)

    return 67, {b"Content-Type": [b"image/png"]}, "", 200
