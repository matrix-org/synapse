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

import sys

from twisted.internet import epollreactor
from twisted.internet.main import installReactor

from synapse.config.homeserver import HomeServerConfig
from synapse.util import Clock

from tests.utils import default_config, setup_test_homeserver


async def make_homeserver(reactor, config=None):
    """
    Make a Homeserver suitable for running benchmarks against.

    Args:
        reactor: A Twisted reactor to run under.
        config: A HomeServerConfig to use, or None.
    """
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
    if hasattr(stor.db.updates, "do_next_background_update"):
        while not await stor.db.updates.has_completed_background_updates():
            await stor.db.updates.do_next_background_update(1)

    def cleanup():
        for i in cleanup_tasks:
            i()

    return hs, clock.sleep, cleanup


def make_reactor():
    """
    Instantiate and install a Twisted reactor suitable for testing (i.e. not the
    default global one).
    """
    reactor = epollreactor.EPollReactor()

    if "twisted.internet.reactor" in sys.modules:
        del sys.modules["twisted.internet.reactor"]
    installReactor(reactor)

    return reactor
