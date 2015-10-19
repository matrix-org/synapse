# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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


from tests import unittest
from tests.utils import MockClock

from synapse.events.builder import EventBuilderFactory
from synapse.crypto.event_signing import add_hashes_and_signatures
from synapse.types import EventID

from unpaddedbase64 import decode_base64

import nacl.signing


# Perform these tests using given secret key so we get entirely deterministic
# signatures output that we can test against.
SIGNING_KEY_SEED = decode_base64(
    "YJDBA9Xnr2sVqXD9Vj7XVUnmFZcZrlw8Md7kMW+3XA1"
)

KEY_ALG = "ed25519"
KEY_VER = 1
KEY_NAME = "%s:%d" % (KEY_ALG, KEY_VER)

HOSTNAME = "domain"


class EventBuilderFactoryWithPredicableIDs(EventBuilderFactory):
    """ A subclass of EventBuilderFactory that generates entirely predicatable
    event IDs, so we can assert on them. """
    def create_event_id(self):
        i = str(self.event_id_count)
        self.event_id_count += 1

        return EventID.create(i, self.hostname).to_string()


class EventSigningTestCase(unittest.TestCase):

    def setUp(self):
        self.event_builder_factory = EventBuilderFactoryWithPredicableIDs(
            clock=MockClock(),
            hostname=HOSTNAME,
        )

        self.signing_key = nacl.signing.SigningKey(SIGNING_KEY_SEED)
        self.signing_key.alg = KEY_ALG
        self.signing_key.version = KEY_VER

    def test_sign(self):
        builder = self.event_builder_factory.new(
            {'type': "X"}
        )
        self.assertEquals(
            builder.build().get_dict(),
            {
                'event_id': "$0:domain",
                'origin': "domain",
                'origin_server_ts': 1000000,
                'signatures': {},
                'type': "X",
                'unsigned': {'age_ts': 1000000},
            },
        )

        add_hashes_and_signatures(builder, HOSTNAME, self.signing_key)

        event = builder.build()

        self.assertTrue(hasattr(event, 'hashes'))
        self.assertTrue('sha256' in event.hashes)
        self.assertEquals(
            event.hashes['sha256'],
            "6tJjLpXtggfke8UxFhAKg82QVkJzvKOVOOSjUDK4ZSI",
        )

        self.assertTrue(hasattr(event, 'signatures'))
        self.assertTrue(HOSTNAME in event.signatures)
        self.assertTrue(KEY_NAME in event.signatures["domain"])
        self.assertEquals(
            event.signatures[HOSTNAME][KEY_NAME],
            "2Wptgo4CwmLo/Y8B8qinxApKaCkBG2fjTWB7AbP5Uy+"
            "aIbygsSdLOFzvdDjww8zUVKCmI02eP9xtyJxc/cLiBA",
        )
