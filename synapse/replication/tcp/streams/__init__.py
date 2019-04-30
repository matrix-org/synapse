# -*- coding: utf-8 -*-
# Copyright 2017 Vector Creations Ltd
# Copyright 2019 New Vector Ltd
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

"""Defines all the valid streams that clients can subscribe to, and the format
of the rows returned by each stream.

Each stream is defined by the following information:

    stream name:        The name of the stream
    row type:           The type that is used to serialise/deserialse the row
    current_token:      The function that returns the current token for the stream
    update_function:    The function that returns a list of updates between two tokens
"""

from . import _base, events, federation

STREAMS_MAP = {
    stream.NAME: stream
    for stream in (
        events.EventsStream,
        _base.BackfillStream,
        _base.PresenceStream,
        _base.TypingStream,
        _base.ReceiptsStream,
        _base.PushRulesStream,
        _base.PushersStream,
        _base.CachesStream,
        _base.PublicRoomsStream,
        _base.DeviceListsStream,
        _base.ToDeviceStream,
        federation.FederationStream,
        _base.TagAccountDataStream,
        _base.AccountDataStream,
        _base.GroupServerStream,
    )
}
