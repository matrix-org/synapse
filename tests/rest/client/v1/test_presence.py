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

import hashlib
import hmac
import json

from mock import Mock

from synapse.http.server import JsonResource
from synapse.rest.client.v1.admin import register_servlets
from synapse.util import Clock

from tests import unittest
from tests.server import (
    ThreadedMemoryReactorClock,
    make_request,
    render,
    setup_test_homeserver,
)


class UserRegisterTestCase(unittest.TestCase):
    def setUp(self):

        self.clock = ThreadedMemoryReactorClock()
        self.hs_clock = Clock(self.clock)

        self.hs = setup_test_homeserver(
            self.addCleanup, http_client=None, clock=self.hs_clock, reactor=self.clock
        )

        self.resource = JsonResource(self.hs)
        register_servlets(self.hs, self.resource)
