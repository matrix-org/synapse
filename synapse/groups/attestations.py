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

"""Attestations ensure that users and groups can't lie about their memberships.

When a user joins a group the HS and GS swap attestations, which allow them
both to independently prove to third parties their membership.These
attestations have a validity period so need to be periodically renewed.

If a user leaves (or gets kicked out of) a group, either side can still use
their attestation to "prove" their membership, until the attestation expires.
Therefore attestations shouldn't be relied on to prove membership in important
cases, but can for less important situtations, e.g. showing a users membership
of groups on their profile, showing flairs, etc.

An attestation is a signed blob of json that looks like:

    {
        "user_id": "@foo:a.example.com",
        "group_id": "+bar:b.example.com",
        "valid_until_ms": 1507994728530,
        "signatures":{"matrix.org":{"ed25519:auto":"..."}}
    }
"""

import logging
import random

from signedjson.sign import sign_json

from twisted.internet import defer

from synapse.api.errors import SynapseError
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.types import get_domain_from_id
from synapse.util.logcontext import run_in_background

logger = logging.getLogger(__name__)


# Default validity duration for new attestations we create
DEFAULT_ATTESTATION_LENGTH_MS = 3 * 24 * 60 * 60 * 1000

# We add some jitter to the validity duration of attestations so that if we
# add lots of users at once we don't need to renew them all at once.
# The jitter is a multiplier picked randomly between the first and second number
DEFAULT_ATTESTATION_JITTER = (0.9, 1.3)

# Start trying to update our attestations when they come this close to expiring
UPDATE_ATTESTATION_TIME_MS = 1 * 24 * 60 * 60 * 1000


class GroupAttestationSigning(object):
    """Creates and verifies group attestations.
    """
    def __init__(self, hs):
        self.keyring = hs.get_keyring()
        self.clock = hs.get_clock()
        self.server_name = hs.hostname
        self.signing_key = hs.config.signing_key[0]

    @defer.inlineCallbacks
    def verify_attestation(self, attestation, group_id, user_id, server_name=None):
        """Verifies that the given attestation matches the given parameters.

        An optional server_name can be supplied to explicitly set which server's
        signature is expected. Otherwise assumes that either the group_id or user_id
        is local and uses the other's server as the one to check.
        """

        if not server_name:
            if get_domain_from_id(group_id) == self.server_name:
                server_name = get_domain_from_id(user_id)
            elif get_domain_from_id(user_id) == self.server_name:
                server_name = get_domain_from_id(group_id)
            else:
                raise Exception("Expected either group_id or user_id to be local")

        if user_id != attestation["user_id"]:
            raise SynapseError(400, "Attestation has incorrect user_id")

        if group_id != attestation["group_id"]:
            raise SynapseError(400, "Attestation has incorrect group_id")
        valid_until_ms = attestation["valid_until_ms"]

        # TODO: We also want to check that *new* attestations that people give
        # us to store are valid for at least a little while.
        if valid_until_ms < self.clock.time_msec():
            raise SynapseError(400, "Attestation expired")

        yield self.keyring.verify_json_for_server(server_name, attestation)

    def create_attestation(self, group_id, user_id):
        """Create an attestation for the group_id and user_id with default
        validity length.
        """
        validity_period = DEFAULT_ATTESTATION_LENGTH_MS
        validity_period *= random.uniform(*DEFAULT_ATTESTATION_JITTER)
        valid_until_ms = int(self.clock.time_msec() + validity_period)

        return sign_json({
            "group_id": group_id,
            "user_id": user_id,
            "valid_until_ms": valid_until_ms,
        }, self.server_name, self.signing_key)


class GroupAttestionRenewer(object):
    """Responsible for sending and receiving attestation updates.
    """

    def __init__(self, hs):
        self.clock = hs.get_clock()
        self.store = hs.get_datastore()
        self.assestations = hs.get_groups_attestation_signing()
        self.transport_client = hs.get_federation_transport_client()
        self.is_mine_id = hs.is_mine_id
        self.attestations = hs.get_groups_attestation_signing()

        self._renew_attestations_loop = self.clock.looping_call(
            self._start_renew_attestations, 30 * 60 * 1000,
        )

    @defer.inlineCallbacks
    def on_renew_attestation(self, group_id, user_id, content):
        """When a remote updates an attestation
        """
        attestation = content["attestation"]

        if not self.is_mine_id(group_id) and not self.is_mine_id(user_id):
            raise SynapseError(400, "Neither user not group are on this server")

        yield self.attestations.verify_attestation(
            attestation,
            user_id=user_id,
            group_id=group_id,
        )

        yield self.store.update_remote_attestion(group_id, user_id, attestation)

        defer.returnValue({})

    def _start_renew_attestations(self):
        return run_as_background_process("renew_attestations", self._renew_attestations)

    @defer.inlineCallbacks
    def _renew_attestations(self):
        """Called periodically to check if we need to update any of our attestations
        """

        now = self.clock.time_msec()

        rows = yield self.store.get_attestations_need_renewals(
            now + UPDATE_ATTESTATION_TIME_MS
        )

        @defer.inlineCallbacks
        def _renew_attestation(group_id, user_id):
            try:
                if not self.is_mine_id(group_id):
                    destination = get_domain_from_id(group_id)
                elif not self.is_mine_id(user_id):
                    destination = get_domain_from_id(user_id)
                else:
                    logger.warn(
                        "Incorrectly trying to do attestations for user: %r in %r",
                        user_id, group_id,
                    )
                    yield self.store.remove_attestation_renewal(group_id, user_id)
                    return

                attestation = self.attestations.create_attestation(group_id, user_id)

                yield self.transport_client.renew_group_attestation(
                    destination, group_id, user_id,
                    content={"attestation": attestation},
                )

                yield self.store.update_attestation_renewal(
                    group_id, user_id, attestation
                )
            except Exception:
                logger.exception("Error renewing attestation of %r in %r",
                                 user_id, group_id)

        for row in rows:
            group_id = row["group_id"]
            user_id = row["user_id"]

            run_in_background(_renew_attestation, group_id, user_id)
