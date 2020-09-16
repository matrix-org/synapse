# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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


import nacl.signing
from unpaddedbase64 import decode_base64

from synapse.api.room_versions import RoomVersions
from synapse.crypto.event_signing import add_hashes_and_signatures
from synapse.events import make_event_from_dict

from tests import unittest

# Perform these tests using given secret key so we get entirely deterministic
# signatures output that we can test against.
SIGNING_KEY_SEED = decode_base64("YJDBA9Xnr2sVqXD9Vj7XVUnmFZcZrlw8Md7kMW+3XA1")

KEY_ALG = "ed25519"
KEY_VER = 1
KEY_NAME = "%s:%d" % (KEY_ALG, KEY_VER)

HOSTNAME = "domain"


class EventSigningTestCase(unittest.TestCase):
    def setUp(self):
        self.signing_key = nacl.signing.SigningKey(SIGNING_KEY_SEED)
        self.signing_key.alg = KEY_ALG
        self.signing_key.version = KEY_VER

    def test_sign_minimal(self):
        event_dict = {
            "event_id": "$0:domain",
            "origin": "domain",
            "origin_server_ts": 1000000,
            "signatures": {},
            "type": "X",
            "unsigned": {"age_ts": 1000000},
        }

        add_hashes_and_signatures(
            RoomVersions.V1, event_dict, HOSTNAME, self.signing_key
        )

        event = make_event_from_dict(event_dict)

        self.assertTrue(hasattr(event, "hashes"))
        self.assertIn("sha256", event.hashes)
        self.assertEquals(
            event.hashes["sha256"], "6tJjLpXtggfke8UxFhAKg82QVkJzvKOVOOSjUDK4ZSI"
        )

        self.assertTrue(hasattr(event, "signatures"))
        self.assertIn(HOSTNAME, event.signatures)
        self.assertIn(KEY_NAME, event.signatures["domain"])
        self.assertEquals(
            event.signatures[HOSTNAME][KEY_NAME],
            "2Wptgo4CwmLo/Y8B8qinxApKaCkBG2fjTWB7AbP5Uy+"
            "aIbygsSdLOFzvdDjww8zUVKCmI02eP9xtyJxc/cLiBA",
        )

    def test_sign_message(self):
        event_dict = {
            "content": {"body": "Here is the message content"},
            "event_id": "$0:domain",
            "origin": "domain",
            "origin_server_ts": 1000000,
            "type": "m.room.message",
            "room_id": "!r:domain",
            "sender": "@u:domain",
            "signatures": {},
            "unsigned": {"age_ts": 1000000},
        }

        add_hashes_and_signatures(
            RoomVersions.V1, event_dict, HOSTNAME, self.signing_key
        )

        event = make_event_from_dict(event_dict)

        self.assertTrue(hasattr(event, "hashes"))
        self.assertIn("sha256", event.hashes)
        self.assertEquals(
            event.hashes["sha256"], "onLKD1bGljeBWQhWZ1kaP9SorVmRQNdN5aM2JYU2n/g"
        )

        self.assertTrue(hasattr(event, "signatures"))
        self.assertIn(HOSTNAME, event.signatures)
        self.assertIn(KEY_NAME, event.signatures["domain"])
        self.assertEquals(
            event.signatures[HOSTNAME][KEY_NAME],
            "Wm+VzmOUOz08Ds+0NTWb1d4CZrVsJSikkeRxh6aCcUw"
            "u6pNC78FunoD7KNWzqFn241eYHYMGCA5McEiVPdhzBA",
        )
