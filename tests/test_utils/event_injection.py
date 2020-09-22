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
from typing import List, Optional, Tuple

import synapse.server
from synapse.api.constants import EventTypes
from synapse.api.room_versions import KNOWN_ROOM_VERSIONS
from synapse.events import EventBase
from synapse.events.snapshot import EventContext

"""
Utility functions for poking events into the storage of the server under test.
"""


async def inject_member_event(
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

    return await inject_event(
        hs,
        room_id=room_id,
        type=EventTypes.Member,
        sender=sender,
        state_key=target,
        content=content,
        **kwargs
    )


async def inject_event(
    hs: synapse.server.HomeServer,
    room_version: Optional[str] = None,
    prev_event_ids: Optional[List[str]] = None,
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
    event, context = await create_event(hs, room_version, prev_event_ids, **kwargs)

    persistence = hs.get_storage().persistence
    assert persistence is not None

    await persistence.persist_event(event, context)

    return event


async def create_event(
    hs: synapse.server.HomeServer,
    room_version: Optional[str] = None,
    prev_event_ids: Optional[List[str]] = None,
    **kwargs
) -> Tuple[EventBase, EventContext]:
    if room_version is None:
        room_version = await hs.get_datastore().get_room_version_id(kwargs["room_id"])

    builder = hs.get_event_builder_factory().for_room_version(
        KNOWN_ROOM_VERSIONS[room_version], kwargs
    )
    event, context = await hs.get_event_creation_handler().create_new_client_event(
        builder, prev_event_ids=prev_event_ids
    )

    return event, context
