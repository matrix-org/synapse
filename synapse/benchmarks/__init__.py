# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.
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

from twisted.internet.defer import Deferred

from synapse.config.homeserver import HomeServerConfig
from synapse.util import Clock

from tests.utils import default_config, setup_test_homeserver, setupdb

DB_SETUP = False


def setup_database():
    global DB_SETUP
    if not DB_SETUP:
        setupdb()
        DB_SETUP = True


async def make_homeserver(reactor, config=None):
    def wait(time):
        d = Deferred()
        reactor.callLater(time, d.callback, True)
        return d

    cleanup_tasks = []

    clock = Clock(reactor)

    if not config:
        config = default_config("test")

    config_obj = HomeServerConfig()
    config_obj.parse_config_dict(config, "", "")

    hs = await setup_test_homeserver(
        cleanup_tasks.append, config=config_obj, reactor=reactor, clock=clock
    )
    stor = hs.get_datastore()

    # Run the database background updates.
    if hasattr(stor, "do_next_background_update"):
        while not await stor.has_completed_background_updates():
            await stor.do_next_background_update(1)

    def cleanup():
        for i in cleanup_tasks:
            i()

    return hs, wait, cleanup
