# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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

from .room import RoomMemberEvent

def prune_event(event):
    """ Prunes the given event of all keys we don't know about or think could
    potentially be dodgy.

    This is used when we "delete" an event. We want to remove all fields that
    the user has specified, but we do want to keep necessary information like
    type, state_key etc.
    """

    # Remove all extraneous fields.
    event.unrecognized_keys = {}

    if event.type == RoomMemberEvent.TYPE:
        new_content = {
            "membership": event.content["membership"]
        }
    else:
        new_content = {}

    event.content = new_content

    return event
