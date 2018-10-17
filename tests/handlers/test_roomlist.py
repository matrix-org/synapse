# -*- coding: utf-8 -*-
# Copyright 2018 New Vector Ltd
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

from synapse.handlers.room_list import RoomListNextBatch

import tests.unittest
import tests.utils


class RoomListTestCase(tests.unittest.TestCase):
    """ Tests RoomList's RoomListNextBatch. """

    def setUp(self):
        pass

    def test_check_read_batch_tokens(self):
        batch_token = RoomListNextBatch(
            stream_ordering="abcdef",
            public_room_stream_id="123",
            current_limit=20,
            direction_is_forward=True,
        ).to_token()
        next_batch = RoomListNextBatch.from_token(batch_token)
        self.assertEquals(next_batch.stream_ordering, "abcdef")
        self.assertEquals(next_batch.public_room_stream_id, "123")
        self.assertEquals(next_batch.current_limit, 20)
        self.assertEquals(next_batch.direction_is_forward, True)
