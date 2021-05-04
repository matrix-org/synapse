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

try:
    from twisted.internet.epollreactor import EPollReactor as Reactor
except ImportError:
    from twisted.internet.pollreactor import PollReactor as Reactor
from twisted.internet.main import installReactor


def make_reactor():
    """
    Instantiate and install a Twisted reactor suitable for testing (i.e. not the
    default global one).
    """
    reactor = Reactor()

    if "twisted.internet.reactor" in sys.modules:
        del sys.modules["twisted.internet.reactor"]
    installReactor(reactor)

    return reactor
