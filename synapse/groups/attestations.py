# -*- coding: utf-8 -*-
# Copyright 2017 Vector Creations Ltd
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

from twisted.internet import defer

from synapse.api.errors import SynapseError
from synapse.types import get_domain_from_id

from signedjson.sign import sign_json


DEFAULT_ATTESTATION_LENGTH_MS = 3 * 24 * 60 * 60 * 1000
MIN_ATTESTATION_LENGTH_MS = 1 * 60 * 60 * 1000
UPDATE_ATTESTATION_TIME_MS = 1 * 24 * 60 * 60 * 1000


class GroupAttestationSigning(object):
    def __init__(self, keyring, clock, server_name):
        self.keyring = keyring
        self.clock = clock
        self.server_name = server_name

    @defer.inlineCallbacks
    def verify_attestation(self, attestation, group_id, user_id, server_name=None):
        if not server_name:
            if get_domain_from_id(group_id) == self.server_name:
                server_name = get_domain_from_id(user_id)
            else:
                server_name = get_domain_from_id(group_id)

        if user_id != attestation["user_id"]:
            raise SynapseError(400, "Attestation has incorrect user_id")

        if group_id != attestation["group_id"]:
            raise SynapseError(400, "Attestation has incorrect group_id")

        valid_until_ms = attestation["valid_until_ms"]
        if valid_until_ms - self.clock.time_msec() < MIN_ATTESTATION_LENGTH_MS:
            raise SynapseError(400, "Attestation not valid for long enough")

        yield self.keyring.verify_json_for_server(server_name, attestation)

    def create_attestation(self, group_id, user_id):
        return sign_json({
            "group_id": group_id,
            "user_id": user_id,
            "valid_until_ms": self.clock.time_msec() + DEFAULT_ATTESTATION_LENGTH_MS,
        }, self.server_name, self.signing_key)
