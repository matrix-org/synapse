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
from synapse.util.logcontext import preserve_fn

from signedjson.sign import sign_json


DEFAULT_ATTESTATION_LENGTH_MS = 3 * 24 * 60 * 60 * 1000
MIN_ATTESTATION_LENGTH_MS = 1 * 60 * 60 * 1000
UPDATE_ATTESTATION_TIME_MS = 1 * 24 * 60 * 60 * 1000


class GroupAttestationSigning(object):
    def __init__(self, hs):
        self.keyring = hs.get_keyring()
        self.clock = hs.get_clock()
        self.server_name = hs.hostname
        self.signing_key = hs.config.signing_key[0]

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


class GroupAttestionRenewer(object):
    def __init__(self, hs):
        self.clock = hs.get_clock()
        self.store = hs.get_datastore()
        self.assestations = hs.get_groups_attestation_signing()
        self.transport_client = hs.get_federation_transport_client()

        self._renew_attestations_loop = self.clock.looping_call(
            self._renew_attestations, 30 * 60 * 1000,
        )

    @defer.inlineCallbacks
    def on_renew_attestation(self, group_id, user_id, content):
        attestation = content["attestation"]

        yield self.attestations.verify_attestation(
            attestation,
            user_id=user_id,
            group_id=group_id,
        )

        yield self.store.update_remote_attestion(group_id, user_id, attestation)

        defer.returnValue({})

    @defer.inlineCallbacks
    def _renew_attestations(self):
        now = self.clock.time_msec()

        rows = yield self.store.get_attestations_need_renewals(
            now + UPDATE_ATTESTATION_TIME_MS
        )

        @defer.inlineCallbacks
        def _renew_attestation(self, group_id, user_id):
            attestation = self.attestations.create_attestation(group_id, user_id)

            if self.hs.is_mine_id(group_id):
                destination = get_domain_from_id(user_id)
            else:
                destination = get_domain_from_id(group_id)

            yield self.transport_client.renew_group_attestation(
                destination, group_id, user_id,
                content={"attestation": attestation},
            )

            yield self.store.update_attestation_renewal(
                group_id, user_id, attestation
            )

        for row in rows:
            group_id = row["group_id"]
            user_id = row["user_id"]

            preserve_fn(_renew_attestation)(group_id, user_id)
