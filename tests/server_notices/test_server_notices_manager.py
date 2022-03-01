# Copyright 2018, 2019 New Vector Ltd
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

from typing import cast
from unittest.mock import Mock

from twisted.internet import defer

from synapse.api.constants import EventTypes, Membership
from synapse.api.room_versions import RoomVersions
from synapse.events import FrozenEvent
from synapse.server_notices.server_notices_manager import ServerNoticesManager
from synapse.storage.roommember import RoomsForUser

from tests import unittest
from tests.unittest import override_config
from tests.utils import default_config

server_notice_config = {
    "system_mxid_localpart": "server",
    "system_mxid_display_name": "display name",
    "system_mxid_avatar_url": "test/url",
    "room_name": "Server Notices",
}


class TestServiceNoticeManager(unittest.HomeserverTestCase):
    def default_config(self):
        config = cast(dict, default_config("test"))
        config.update({"server_notices": server_notice_config})

        # apply any additional config which was specified via the override_config
        # decorator.
        if self._extra_config is not None:
            config.update(self._extra_config)

        return config

    def prepare(self, reactor, clock, hs):
        self.server_notices_manager = self.hs.get_server_notices_manager()

        self.server_notices_manager._event_creation_handler.create_and_send_nonmember_event = Mock(
            return_value=defer.succeed(
                (FrozenEvent({"event_id": "$notice_event123"}, RoomVersions.V1), 0)
            )
        )

        self.server_notices_manager._room_member_handler.update_membership = Mock(
            return_value=defer.succeed(("$updated_membership123", 1))
        )

        self.user_id = "@user_id:test"
        self.notice_message = {"content": "a new message from server", type: "m.text"}

    @override_config(
        {
            "server_notices": {
                **server_notice_config,
                "system_mxid_display_name": "new display name",
            }
        }
    )
    def test_update_notice_user_name_when_changed(self):
        """
        Tests that existing server notices user name in room is updated when is
        different from the one in homeserver config.
        """
        self._mock_existing_notice_room(
            self.server_notices_manager, server_notice_config
        )

        self.get_success(
            self.server_notices_manager.send_notice(
                self.user_id, self.notice_message, EventTypes.Message
            )
        )

        self.server_notices_manager._room_member_handler.update_membership.assert_called_once()
        call_args_content = self.server_notices_manager._room_member_handler.update_membership.call_args.kwargs[
            "content"
        ]

        assert call_args_content == {
            "displayname": self.hs.config.servernotices.server_notices_mxid_display_name,
            "avatar_url": self.hs.config.servernotices.server_notices_mxid_avatar_url,
        }

    @override_config(
        {
            "server_notices": {
                **server_notice_config,
                "system_mxid_avatar_url": "test/new-url",
            }
        }
    )
    def test_update_notice_user_avatar_when_changed(self):
        """
        Tests that existing server notices user avatar in room is updated when is
        different from the one in homeserver config.
        """
        self._mock_existing_notice_room(
            self.server_notices_manager, server_notice_config
        )

        self.get_success(
            self.server_notices_manager.send_notice(
                self.user_id, self.notice_message, EventTypes.Message
            )
        )

        self.server_notices_manager._room_member_handler.update_membership.assert_called_once()
        call_args_content = self.server_notices_manager._room_member_handler.update_membership.call_args.kwargs[
            "content"
        ]

        assert call_args_content == {
            "displayname": self.hs.config.servernotices.server_notices_mxid_display_name,
            "avatar_url": self.hs.config.servernotices.server_notices_mxid_avatar_url,
        }

    def test_doesnt_update_notice_user_profile_when_not_changed(self):
        """
        Tests that existing server notices profile in room is not updated when is
        equal to the one in homeserver config.
        """
        self._mock_existing_notice_room(
            self.server_notices_manager, server_notice_config
        )

        self.get_success(
            self.server_notices_manager.send_notice(
                self.user_id, self.notice_message, EventTypes.Message
            )
        )

        self.server_notices_manager._room_member_handler.update_membership.assert_not_called()

    def _mock_existing_notice_room(
        self, server_notices_manager: ServerNoticesManager, server_notice_config: dict
    ):
        """
        Mocks ServerNoticesManager dependencies used for reading info
        about existing server notice room.
        """
        # Ignored type error: Cannot assign to a method
        #  https://github.com/python/mypy/issues/2427
        server_notices_manager._store.get_rooms_for_local_user_where_membership_is = Mock(  # type: ignore
            return_value=defer.succeed(
                [
                    RoomsForUser(
                        room_id="!something:test",
                        event_id="$abc123",
                        membership=Membership.JOIN,
                        sender="@server:test",
                        room_version_id="1",
                        stream_ordering=0,
                    )
                ]
            )
        )

        # Ignored type error: Cannot assign to a method
        #  https://github.com/python/mypy/issues/2427
        server_notices_manager._store.get_users_in_room = Mock(  # type: ignore
            return_value=defer.succeed([server_notices_manager.server_notices_mxid])
        )

        notice_user_profile_in_room = {
            "displayname": server_notice_config["system_mxid_display_name"],
            "avatar_url": server_notice_config["system_mxid_avatar_url"],
        }
        # Ignored type error: Cannot assign to a method
        #  https://github.com/python/mypy/issues/2427
        server_notices_manager._message_handler.get_room_data = Mock(  # type: ignore
            return_value=defer.succeed(
                FrozenEvent(
                    {
                        "event_id": "$notice_user_state_123",
                        "content": notice_user_profile_in_room,
                    },
                    RoomVersions.V1,
                )
            )
        )
