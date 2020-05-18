# -*- coding: utf-8 -*-
# Copyright 2018 New Vector Ltd
# Copyright 2020 The Matrix.org Foundation C.I.C
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

from typing import Optional, Tuple

import synapse.server
from synapse.api.constants import EventTypes
from synapse.api.room_versions import KNOWN_ROOM_VERSIONS
from synapse.events import EventBase
from synapse.events.snapshot import EventContext
from synapse.types import Collection

from tests.test_utils import get_awaitable_result


"""
Utility functions for poking events into the storage of the server under test.
"""


def inject_member_event(
    hs: synapse.server.HomeServer,
    room_id: str,
    sender: str,
    membership: str,
    target: Optional[str] = None,
    extra_content: Optional[dict] = None,
    **kwargs
) -> EventBase:
    """Inject a membership event into a room."""
    if target is None:
        target = sender

    content = {"membership": membership}
    if extra_content:
        content.update(extra_content)

    return inject_event(
        hs,
        room_id=room_id,
        type=EventTypes.Member,
        sender=sender,
        state_key=target,
        content=content,
        **kwargs
    )


def inject_event(
    hs: synapse.server.HomeServer,
    room_version: Optional[str] = None,
    prev_event_ids: Optional[Collection[str]] = None,
    **kwargs
) -> EventBase:
    """Inject a generic event into a room

    Args:
        hs: the homeserver under test
        room_version: the version of the room we're inserting into.
            if not specified, will be looked up
        prev_event_ids: prev_events for the event. If not specified, will be looked up
        kwargs: fields for the event to be created
    """
    test_reactor = hs.get_reactor()

    event, context = create_event(hs, room_version, prev_event_ids, **kwargs)

    d = hs.get_storage().persistence.persist_event(event, context)
    test_reactor.advance(0)
    get_awaitable_result(d)

    return event


def create_event(
    hs: synapse.server.HomeServer,
    room_version: Optional[str] = None,
    prev_event_ids: Optional[Collection[str]] = None,
    **kwargs
) -> Tuple[EventBase, EventContext]:
    test_reactor = hs.get_reactor()

    if room_version is None:
        d = hs.get_datastore().get_room_version_id(kwargs["room_id"])
        test_reactor.advance(0)
        room_version = get_awaitable_result(d)

    builder = hs.get_event_builder_factory().for_room_version(
        KNOWN_ROOM_VERSIONS[room_version], kwargs
    )
    d = hs.get_event_creation_handler().create_new_client_event(
        builder, prev_event_ids=prev_event_ids
    )
    test_reactor.advance(0)
    event, context = get_awaitable_result(d)

    return event, context
