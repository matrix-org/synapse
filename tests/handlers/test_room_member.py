from unittest.mock import Mock, patch

from twisted.test.proto_helpers import MemoryReactor

import synapse.rest.admin
import synapse.rest.client.login
import synapse.rest.client.room
from synapse.api.constants import EventTypes, Membership
from synapse.api.errors import LimitExceededError, SynapseError
from synapse.crypto.event_signing import add_hashes_and_signatures
from synapse.events import FrozenEventV3
from synapse.federation.federation_client import SendJoinResult
from synapse.server import HomeServer
from synapse.types import UserID, create_requester
from synapse.util import Clock

from tests.replication._base import BaseMultiWorkerStreamTestCase
from tests.server import make_request
from tests.test_utils import make_awaitable
from tests.unittest import (
    FederatingHomeserverTestCase,
    HomeserverTestCase,
    override_config,
)


class TestJoinsLimitedByPerRoomRateLimiter(FederatingHomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets,
        synapse.rest.client.login.register_servlets,
        synapse.rest.client.room.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.handler = hs.get_room_member_handler()

        # Create three users.
        self.alice = self.register_user("alice", "pass")
        self.alice_token = self.login("alice", "pass")
        self.bob = self.register_user("bob", "pass")
        self.bob_token = self.login("bob", "pass")
        self.chris = self.register_user("chris", "pass")
        self.chris_token = self.login("chris", "pass")

        # Create a room on this homeserver. Note that this counts as a join: it
        # contributes to the rate limter's count of actions
        self.room_id = self.helper.create_room_as(self.alice, tok=self.alice_token)

        self.intially_unjoined_room_id = f"!example:{self.OTHER_SERVER_NAME}"

    @override_config({"rc_joins_per_room": {"per_second": 0, "burst_count": 2}})
    def test_local_user_local_joins_contribute_to_limit_and_are_limited(self) -> None:
        # The rate limiter has accumulated one token from Alice's join after the create
        # event.
        # Try joining the room as Bob.
        self.get_success(
            self.handler.update_membership(
                requester=create_requester(self.bob),
                target=UserID.from_string(self.bob),
                room_id=self.room_id,
                action=Membership.JOIN,
            )
        )

        # The rate limiter bucket is full. A second join should be denied.
        self.get_failure(
            self.handler.update_membership(
                requester=create_requester(self.chris),
                target=UserID.from_string(self.chris),
                room_id=self.room_id,
                action=Membership.JOIN,
            ),
            LimitExceededError,
        )

    @override_config({"rc_joins_per_room": {"per_second": 0, "burst_count": 2}})
    def test_local_user_profile_edits_dont_contribute_to_limit(self) -> None:
        # The rate limiter has accumulated one token from Alice's join after the create
        # event. Alice should still be able to change her displayname.
        self.get_success(
            self.handler.update_membership(
                requester=create_requester(self.alice),
                target=UserID.from_string(self.alice),
                room_id=self.room_id,
                action=Membership.JOIN,
                content={"displayname": "Alice Cooper"},
            )
        )

        # Still room in the limiter bucket. Chris's join should be accepted.
        self.get_success(
            self.handler.update_membership(
                requester=create_requester(self.chris),
                target=UserID.from_string(self.chris),
                room_id=self.room_id,
                action=Membership.JOIN,
            )
        )

    @override_config({"rc_joins_per_room": {"per_second": 0, "burst_count": 1}})
    def test_remote_joins_contribute_to_rate_limit(self) -> None:
        # Join once, to fill the rate limiter bucket.
        #
        # To do this we have to mock the responses from the remote homeserver.
        # We also patch out a bunch of event checks on our end. All we're really
        # trying to check here is that remote joins will bump the rate limter when
        # they are persisted.
        create_event_source = {
            "auth_events": [],
            "content": {
                "creator": f"@creator:{self.OTHER_SERVER_NAME}",
                "room_version": self.hs.config.server.default_room_version.identifier,
            },
            "depth": 0,
            "origin_server_ts": 0,
            "prev_events": [],
            "room_id": self.intially_unjoined_room_id,
            "sender": f"@creator:{self.OTHER_SERVER_NAME}",
            "state_key": "",
            "type": EventTypes.Create,
        }
        self.add_hashes_and_signatures_from_other_server(
            create_event_source,
            self.hs.config.server.default_room_version,
        )
        create_event = FrozenEventV3(
            create_event_source,
            self.hs.config.server.default_room_version,
            {},
            None,
        )

        join_event_source = {
            "auth_events": [create_event.event_id],
            "content": {"membership": "join"},
            "depth": 1,
            "origin_server_ts": 100,
            "prev_events": [create_event.event_id],
            "sender": self.bob,
            "state_key": self.bob,
            "room_id": self.intially_unjoined_room_id,
            "type": EventTypes.Member,
        }
        add_hashes_and_signatures(
            self.hs.config.server.default_room_version,
            join_event_source,
            self.hs.hostname,
            self.hs.signing_key,
        )
        join_event = FrozenEventV3(
            join_event_source,
            self.hs.config.server.default_room_version,
            {},
            None,
        )

        mock_make_membership_event = Mock(
            return_value=make_awaitable(
                (
                    self.OTHER_SERVER_NAME,
                    join_event,
                    self.hs.config.server.default_room_version,
                )
            )
        )
        mock_send_join = Mock(
            return_value=make_awaitable(
                SendJoinResult(
                    join_event,
                    self.OTHER_SERVER_NAME,
                    state=[create_event],
                    auth_chain=[create_event],
                    partial_state=False,
                    servers_in_room=[],
                )
            )
        )

        with patch.object(
            self.handler.federation_handler.federation_client,
            "make_membership_event",
            mock_make_membership_event,
        ), patch.object(
            self.handler.federation_handler.federation_client,
            "send_join",
            mock_send_join,
        ), patch(
            "synapse.event_auth._is_membership_change_allowed",
            return_value=None,
        ), patch(
            "synapse.handlers.federation_event.check_state_dependent_auth_rules",
            return_value=None,
        ):
            self.get_success(
                self.handler.update_membership(
                    requester=create_requester(self.bob),
                    target=UserID.from_string(self.bob),
                    room_id=self.intially_unjoined_room_id,
                    action=Membership.JOIN,
                    remote_room_hosts=[self.OTHER_SERVER_NAME],
                )
            )

            # Try to join as Chris. Should get denied.
            self.get_failure(
                self.handler.update_membership(
                    requester=create_requester(self.chris),
                    target=UserID.from_string(self.chris),
                    room_id=self.intially_unjoined_room_id,
                    action=Membership.JOIN,
                    remote_room_hosts=[self.OTHER_SERVER_NAME],
                ),
                LimitExceededError,
            )

    # TODO: test that remote joins to a room are rate limited.
    #   Could do this by setting the burst count to 1, then:
    #   - remote-joining a room
    #   - immediately leaving
    #   - trying to remote-join again.


class TestReplicatedJoinsLimitedByPerRoomRateLimiter(BaseMultiWorkerStreamTestCase):
    servlets = [
        synapse.rest.admin.register_servlets,
        synapse.rest.client.login.register_servlets,
        synapse.rest.client.room.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.handler = hs.get_room_member_handler()

        # Create three users.
        self.alice = self.register_user("alice", "pass")
        self.alice_token = self.login("alice", "pass")
        self.bob = self.register_user("bob", "pass")
        self.bob_token = self.login("bob", "pass")
        self.chris = self.register_user("chris", "pass")
        self.chris_token = self.login("chris", "pass")

        # Create a room on this homeserver.
        # Note that this counts as a
        self.room_id = self.helper.create_room_as(self.alice, tok=self.alice_token)
        self.intially_unjoined_room_id = "!example:otherhs"

    @override_config({"rc_joins_per_room": {"per_second": 0, "burst_count": 2}})
    def test_local_users_joining_on_another_worker_contribute_to_rate_limit(
        self,
    ) -> None:
        # The rate limiter has accumulated one token from Alice's join after the create
        # event.
        self.replicate()

        # Spawn another worker and have bob join via it.
        worker_app = self.make_worker_hs(
            "synapse.app.generic_worker", extra_config={"worker_name": "other worker"}
        )
        worker_site = self._hs_to_site[worker_app]
        channel = make_request(
            self.reactor,
            worker_site,
            "POST",
            f"/_matrix/client/v3/rooms/{self.room_id}/join",
            access_token=self.bob_token,
        )
        self.assertEqual(channel.code, 200, channel.json_body)

        # wait for join to arrive over replication
        self.replicate()

        # Try to join as Chris on the worker. Should get denied because Alice
        # and Bob have both joined the room.
        self.get_failure(
            worker_app.get_room_member_handler().update_membership(
                requester=create_requester(self.chris),
                target=UserID.from_string(self.chris),
                room_id=self.room_id,
                action=Membership.JOIN,
            ),
            LimitExceededError,
        )

        # Try to join as Chris on the original worker. Should get denied because Alice
        # and Bob have both joined the room.
        self.get_failure(
            self.handler.update_membership(
                requester=create_requester(self.chris),
                target=UserID.from_string(self.chris),
                room_id=self.room_id,
                action=Membership.JOIN,
            ),
            LimitExceededError,
        )


class RoomMemberMasterHandlerTestCase(HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets,
        synapse.rest.client.login.register_servlets,
        synapse.rest.client.room.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.handler = hs.get_room_member_handler()
        self.store = hs.get_datastores().main

        # Create two users.
        self.alice = self.register_user("alice", "pass")
        self.alice_ID = UserID.from_string(self.alice)
        self.alice_token = self.login("alice", "pass")
        self.bob = self.register_user("bob", "pass")
        self.bob_ID = UserID.from_string(self.bob)
        self.bob_token = self.login("bob", "pass")

        # Create a room on this homeserver.
        self.room_id = self.helper.create_room_as(self.alice, tok=self.alice_token)

    def test_leave_and_forget(self) -> None:
        """Tests that forget a room is successfully. The test is performed with two users,
        as forgetting by the last user respectively after all users had left the
        is a special edge case."""
        self.helper.join(self.room_id, user=self.bob, tok=self.bob_token)

        # alice is not the last room member that leaves and forgets the room
        self.helper.leave(self.room_id, user=self.alice, tok=self.alice_token)
        self.get_success(self.handler.forget(self.alice_ID, self.room_id))
        self.assertTrue(
            self.get_success(self.store.did_forget(self.alice, self.room_id))
        )

        # the server has not forgotten the room
        self.assertFalse(
            self.get_success(self.store.is_locally_forgotten_room(self.room_id))
        )

    def test_leave_and_forget_last_user(self) -> None:
        """Tests that forget a room is successfully when the last user has left the room."""

        # alice is the last room member that leaves and forgets the room
        self.helper.leave(self.room_id, user=self.alice, tok=self.alice_token)
        self.get_success(self.handler.forget(self.alice_ID, self.room_id))
        self.assertTrue(
            self.get_success(self.store.did_forget(self.alice, self.room_id))
        )

        # the server has forgotten the room
        self.assertTrue(
            self.get_success(self.store.is_locally_forgotten_room(self.room_id))
        )

    def test_forget_when_not_left(self) -> None:
        """Tests that a user cannot not forgets a room that has not left."""
        self.get_failure(self.handler.forget(self.alice_ID, self.room_id), SynapseError)

    def test_rejoin_forgotten_by_user(self) -> None:
        """Test that a user that has forgotten a room can do a re-join.
        The room was not forgotten from the local server.
        One local user is still member of the room."""
        self.helper.join(self.room_id, user=self.bob, tok=self.bob_token)

        self.helper.leave(self.room_id, user=self.alice, tok=self.alice_token)
        self.get_success(self.handler.forget(self.alice_ID, self.room_id))
        self.assertTrue(
            self.get_success(self.store.did_forget(self.alice, self.room_id))
        )

        # the server has not forgotten the room
        self.assertFalse(
            self.get_success(self.store.is_locally_forgotten_room(self.room_id))
        )

        self.helper.join(self.room_id, user=self.alice, tok=self.alice_token)
        # TODO: A join to a room does not invalidate the forgotten cache
        # see https://github.com/matrix-org/synapse/issues/13262
        self.store.did_forget.invalidate_all()
        self.assertFalse(
            self.get_success(self.store.did_forget(self.alice, self.room_id))
        )
