# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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

from twisted.trial import unittest

from synapse.federation.pdu_codec import (
    PduCodec, encode_event_id, decode_event_id
)
from synapse.federation.units import Pdu
#from synapse.api.events.room import MessageEvent

from synapse.server import HomeServer

from mock import Mock


class PduCodecTestCase(unittest.TestCase):
    def setUp(self):
        self.hs = HomeServer("blargle.net")
        self.event_factory = self.hs.get_event_factory()

        self.codec = PduCodec(self.hs)

    def test_decode_event_id(self):
        self.assertEquals(
            ("foo", "bar.com"),
            decode_event_id("foo@bar.com", "A")
        )

        self.assertEquals(
            ("foo", "bar.com"),
            decode_event_id("foo", "bar.com")
        )

    def test_encode_event_id(self):
        self.assertEquals("A@B", encode_event_id("A", "B"))

    def test_codec_event_id(self):
        event_id = "aa@bb.com"

        self.assertEquals(
            event_id,
            encode_event_id(*decode_event_id(event_id, None))
        )

        pdu_id = ("aa", "bb.com")

        self.assertEquals(
            pdu_id,
            decode_event_id(encode_event_id(*pdu_id), None)
        )

    def test_event_from_pdu(self):
        pdu = Pdu(
            pdu_id="foo",
            context="rooooom",
            pdu_type="m.room.message",
            origin="bar.com",
            ts=12345,
            depth=5,
            prev_pdus=[("alice", "bob.com")],
            is_state=False,
            content={"msgtype": u"test"},
        )

        event = self.codec.event_from_pdu(pdu)

        self.assertEquals("foo@bar.com", event.event_id)
        self.assertEquals(pdu.context, event.room_id)
        self.assertEquals(pdu.is_state, event.is_state)
        self.assertEquals(pdu.depth, event.depth)
        self.assertEquals(["alice@bob.com"], event.prev_events)
        self.assertEquals(pdu.content, event.content)

    def test_pdu_from_event(self):
        event = self.event_factory.create_event(
            etype="m.room.message",
            event_id="gargh_id",
            room_id="rooom",
            user_id="sender",
            content={"msgtype": u"test"},
        )

        pdu = self.codec.pdu_from_event(event)

        self.assertEquals(event.event_id, pdu.pdu_id)
        self.assertEquals(self.hs.hostname, pdu.origin)
        self.assertEquals(event.room_id, pdu.context)
        self.assertEquals(event.content, pdu.content)
        self.assertEquals(event.type, pdu.pdu_type)

        event = self.event_factory.create_event(
            etype="m.room.message",
            event_id="gargh_id@bob.com",
            room_id="rooom",
            user_id="sender",
            content={"msgtype": u"test"},
        )

        pdu = self.codec.pdu_from_event(event)

        self.assertEquals("gargh_id", pdu.pdu_id)
        self.assertEquals("bob.com", pdu.origin)
        self.assertEquals(event.room_id, pdu.context)
        self.assertEquals(event.content, pdu.content)
        self.assertEquals(event.type, pdu.pdu_type)

    def test_event_from_state_pdu(self):
        pdu = Pdu(
            pdu_id="foo",
            context="rooooom",
            pdu_type="m.room.topic",
            origin="bar.com",
            ts=12345,
            depth=5,
            prev_pdus=[("alice", "bob.com")],
            is_state=True,
            content={"topic": u"test"},
            state_key="",
        )

        event = self.codec.event_from_pdu(pdu)

        self.assertEquals("foo@bar.com", event.event_id)
        self.assertEquals(pdu.context, event.room_id)
        self.assertEquals(pdu.is_state, event.is_state)
        self.assertEquals(pdu.depth, event.depth)
        self.assertEquals(["alice@bob.com"], event.prev_events)
        self.assertEquals(pdu.content, event.content)
        self.assertEquals(pdu.state_key, event.state_key)

    def test_pdu_from_state_event(self):
        event = self.event_factory.create_event(
            etype="m.room.topic",
            event_id="gargh_id",
            room_id="rooom",
            user_id="sender",
            content={"topic": u"test"},
        )

        pdu = self.codec.pdu_from_event(event)

        self.assertEquals(event.event_id, pdu.pdu_id)
        self.assertEquals(self.hs.hostname, pdu.origin)
        self.assertEquals(event.room_id, pdu.context)
        self.assertEquals(event.content, pdu.content)
        self.assertEquals(event.type, pdu.pdu_type)
        self.assertEquals(event.state_key, pdu.state_key)
