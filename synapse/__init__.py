# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018-2019 New Vector Ltd
# Copyright 2023 The Matrix.org Foundation C.I.C.
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

""" This is an implementation of a Matrix homeserver.
"""

import os
import sys
from typing import Any, Dict

from PIL import ImageFile

from synapse.util.rust import check_rust_lib_up_to_date
from synapse.util.stringutils import strtobool

# Allow truncated JPEG images to be thumbnailed.
ImageFile.LOAD_TRUNCATED_IMAGES = True

# Check that we're not running on an unsupported Python version.
#
# Note that we use an (unneeded) variable here so that pyupgrade doesn't nuke the
# if-statement completely.
py_version = sys.version_info
if py_version < (3, 8):
    print("Synapse requires Python 3.8 or above.")
    sys.exit(1)

# Allow using the asyncio reactor via env var.
if strtobool(os.environ.get("SYNAPSE_ASYNC_IO_REACTOR", "0")):
    from incremental import Version

    import twisted

    # We need a bugfix that is included in Twisted 21.2.0:
    # https://twistedmatrix.com/trac/ticket/9787
    if twisted.version < Version("Twisted", 21, 2, 0):
        print("Using asyncio reactor requires Twisted>=21.2.0")
        sys.exit(1)

    import asyncio

    from twisted.internet import asyncioreactor

    asyncioreactor.install(asyncio.get_event_loop())

# Twisted and canonicaljson will fail to import when this file is executed to
# get the __version__ during a fresh install. That's OK and subsequent calls to
# actually start Synapse will import these libraries fine.
try:
    from twisted.internet import protocol
    from twisted.internet.protocol import Factory
    from twisted.names.dns import DNSDatagramProtocol

    protocol.Factory.noisy = False
    Factory.noisy = False
    DNSDatagramProtocol.noisy = False
except ImportError:
    pass

# Teach canonicaljson how to serialise immutabledicts.
try:
    from canonicaljson import register_preserialisation_callback
    from immutabledict import immutabledict

    def _immutabledict_cb(d: immutabledict) -> Dict[str, Any]:
        try:
            return d._dict
        except Exception:
            # Paranoia: fall back to a `dict()` call, in case a future version of
            # immutabledict removes `_dict` from the implementation.
            return dict(d)

    register_preserialisation_callback(immutabledict, _immutabledict_cb)
except ImportError:
    pass

import synapse.util  # noqa: E402

__version__ = synapse.util.SYNAPSE_VERSION

if bool(os.environ.get("SYNAPSE_TEST_PATCH_LOG_CONTEXTS", False)):
    # We import here so that we don't have to install a bunch of deps when
    # running the packaging tox test.
    from synapse.util.patch_inline_callbacks import do_patch

    do_patch()


check_rust_lib_up_to_date()
