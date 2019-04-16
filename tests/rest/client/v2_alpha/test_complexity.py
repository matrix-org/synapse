# -*- coding: utf-8 -*-
# Copyright 2019 Matrix.org Foundation
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

from mock import Mock

from synapse.rest.client.v1 import admin, login, room
from synapse.rest.client.v2_alpha import room_complexity

from tests import unittest

class RoomComplexityTests(unittest.HomeserverTestCase):

    servlets = [
        admin.register_servlets,
        room.register_servlets,
        login.register_servlets,
        room_complexity.register_servlets,
    ]

    def test_complexity_simple(self):

