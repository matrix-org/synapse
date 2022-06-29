from http import HTTPStatus
from unittest.mock import patch

from twisted.test.proto_helpers import MemoryReactor

import synapse.rest.admin
import synapse.rest.client.login
import synapse.rest.client.room
from synapse.api.constants import Membership
from synapse.api.errors import LimitExceededError
from synapse.server import HomeServer
from synapse.types import UserID, create_requester
from synapse.util import Clock

from tests.replication._base import RedisMultiWorkerStreamTestCase
from tests.server import make_request
from tests.test_utils import make_awaitable
from tests.unittest import HomeserverTestCase, override_config


class TestJoinsLimitedByPerRoomRateLimiter(HomeserverTestCase):
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
        # Join once, to fill the rate limiter bucket. Patch out the `_remote_join" call
        # because there is no other homeserver for us to join via.
        with patch.object(
            self.handler,
            "_remote_join",
            return_value=make_awaitable(("$dummy_event", 1000)),
        ):
            self.get_success(
                self.handler.update_membership(
                    requester=create_requester(self.bob),
                    target=UserID.from_string(self.bob),
                    room_id=self.intially_unjoined_room_id,
                    action=Membership.JOIN,
                )
            )

        # Try to join as Chris. Should get denied.
        self.get_failure(
            self.handler.update_membership(
                requester=create_requester(self.chris),
                target=UserID.from_string(self.chris),
                room_id=self.intially_unjoined_room_id,
                action=Membership.JOIN,
            ),
            LimitExceededError,
        )

    # TODO: test that remote joins to a room are rate limited.
    #   Could do this by setting the burst count to 1, then:
    #   - remote-joining a room
    #   - immediately leaving
    #   - trying to remote-join again.


class TestReplicatedJoinsLimitedByPerRoomRateLimiter(RedisMultiWorkerStreamTestCase):
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
        self.assertEqual(channel.code, HTTPStatus.OK, channel.json_body)

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
