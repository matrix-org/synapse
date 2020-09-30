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

logger = logging.getLogger(__name__)


class EventPersisterShardTestCase(BaseMultiWorkerStreamTestCase):
    """Checks event persisting sharding works
    """

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
        """Simple test that rooms can be created and joined when there are
        multiple event persisters.
        """

        self.make_worker_hs(
            "synapse.app.generic_worker", {"worker_name": "worker1"},
        )

        self.make_worker_hs(
            "synapse.app.generic_worker", {"worker_name": "worker2"},
        )

        user_id = self.register_user("user", "pass")
        access_token = self.login("user", "pass")

        # Create a room
        room = self.helper.create_room_as(user_id, tok=access_token)

        # The other user joins
        self.helper.join(
            room=room, user=self.other_user_id, tok=self.other_access_token
        )

        # The other user sends some messages
        self.helper.send(room, body="Hi!", tok=self.other_access_token)
