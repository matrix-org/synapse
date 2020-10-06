# -*- coding: utf-8 -*-
# Copyright 2020 The Matrix.org Foundation C.I.C.
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
import logging

from synapse.rest import admin
from synapse.rest.client.v1 import login, room

from tests.replication._base import BaseMultiWorkerStreamTestCase
from tests.utils import USE_POSTGRES_FOR_TESTS

logger = logging.getLogger(__name__)


class EventPersisterShardTestCase(BaseMultiWorkerStreamTestCase):
    """Checks event persisting sharding works
    """

    # Event persister sharding requires postgres (due to needing
    # `MutliWriterIdGenerator`).
    if not USE_POSTGRES_FOR_TESTS:
        skip = "Requires Postgres"

    servlets = [
        admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):
        # Register a user who sends a message that we'll get notified about
        self.other_user_id = self.register_user("otheruser", "pass")
        self.other_access_token = self.login("otheruser", "pass")

    def default_config(self):
        conf = super().default_config()
        conf["redis"] = {"enabled": "true"}
        conf["stream_writers"] = {"events": ["worker1", "worker2"]}
        conf["instance_map"] = {
            "worker1": {"host": "testserv", "port": 1001},
            "worker2": {"host": "testserv", "port": 1002},
        }
        return conf

    def test_basic(self):
        """Simple test to ensure that multiple rooms can be created and joined,
        and that different rooms get handled by different instances.
        """

        self.make_worker_hs(
            "synapse.app.generic_worker", {"worker_name": "worker1"},
        )

        self.make_worker_hs(
            "synapse.app.generic_worker", {"worker_name": "worker2"},
        )

        persisted_on_1 = False
        persisted_on_2 = False

        store = self.hs.get_datastore()

        user_id = self.register_user("user", "pass")
        access_token = self.login("user", "pass")

        # Keep making new rooms until we see rooms being persisted on both
        # workers.
        for _ in range(10):
            # Create a room
            room = self.helper.create_room_as(user_id, tok=access_token)

            # The other user joins
            self.helper.join(
                room=room, user=self.other_user_id, tok=self.other_access_token
            )

            # The other user sends some messages
            rseponse = self.helper.send(room, body="Hi!", tok=self.other_access_token)
            event_id = rseponse["event_id"]

            # The event position includes which instance persisted the event.
            pos = self.get_success(store.get_position_for_event(event_id))

            persisted_on_1 |= pos.instance_name == "worker1"
            persisted_on_2 |= pos.instance_name == "worker2"

            if persisted_on_1 and persisted_on_2:
                break

        self.assertTrue(persisted_on_1)
        self.assertTrue(persisted_on_2)
