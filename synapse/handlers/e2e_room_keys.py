# -*- coding: utf-8 -*-
# Copyright 2017 New Vector Ltd
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

import ujson as json
import logging

from canonicaljson import encode_canonical_json
from twisted.internet import defer

from synapse.api.errors import SynapseError, CodeMessageException
from synapse.types import get_domain_from_id
from synapse.util.logcontext import preserve_fn, make_deferred_yieldable
from synapse.util.retryutils import NotRetryingDestination

logger = logging.getLogger(__name__)


class E2eRoomKeysHandler(object):
    def __init__(self, hs):
        self.store = hs.get_datastore()

    @defer.inlineCallbacks
    def get_room_keys(self, user_id, version, room_id, session_id):
        results = yield self.store.get_e2e_room_keys(user_id, version, room_id, session_id)
        defer.returnValue(results)

    @defer.inlineCallbacks
    def upload_room_keys(self, user_id, version, room_keys):

        # TODO: Validate the JSON to make sure it has the right keys.

        # go through the room_keys
        for room_id in room_keys['rooms']:
            for session_id in room_keys['rooms'][room_id]['sessions']:
                session = room_keys['rooms'][room_id]['sessions'][session_id]

                # get a lock

                # get the room_key for this particular row
                yield self.store.get_e2e_room_key()

                # check whether we merge or not
                if()

                # if so, we set it
                yield self.store.set_e2e_room_key()

                # release the lock
