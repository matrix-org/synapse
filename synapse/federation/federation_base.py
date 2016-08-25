# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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

from synapse.events.utils import prune_event

from synapse.crypto.event_signing import check_event_content_hash

from synapse.api.errors import SynapseError

from synapse.util import unwrapFirstError
from synapse.util.logcontext import preserve_fn, preserve_context_over_deferred

import logging


logger = logging.getLogger(__name__)


class FederationBase(object):
    def __init__(self, hs):
        pass

    @defer.inlineCallbacks
    def _check_sigs_and_hash_and_fetch(self, origin, pdus, outlier=False,
                                       include_none=False):
        """Takes a list of PDUs and checks the signatures and hashs of each
        one. If a PDU fails its signature check then we check if we have it in
        the database and if not then request if from the originating server of
        that PDU.

        If a PDU fails its content hash check then it is redacted.

        The given list of PDUs are not modified, instead the function returns
        a new list.

        Args:
            pdu (list)
            outlier (bool)

        Returns:
            Deferred : A list of PDUs that have valid signatures and hashes.
        """
        deferreds = self._check_sigs_and_hashes(pdus)

        def callback(pdu):
            return pdu

        def errback(failure, pdu):
            failure.trap(SynapseError)
            return None

        def try_local_db(res, pdu):
            if not res:
                # Check local db.
                return self.store.get_event(
                    pdu.event_id,
                    allow_rejected=True,
                    allow_none=True,
                )
            return res

        def try_remote(res, pdu):
            if not res and pdu.origin != origin:
                return self.get_pdu(
                    destinations=[pdu.origin],
                    event_id=pdu.event_id,
                    outlier=outlier,
                    timeout=10000,
                ).addErrback(lambda e: None)
            return res

        def warn(res, pdu):
            if not res:
                logger.warn(
                    "Failed to find copy of %s with valid signature",
                    pdu.event_id,
                )
            return res

        for pdu, deferred in zip(pdus, deferreds):
            deferred.addCallbacks(
                callback, errback, errbackArgs=[pdu]
            ).addCallback(
                try_local_db, pdu
            ).addCallback(
                try_remote, pdu
            ).addCallback(
                warn, pdu
            )

        valid_pdus = yield preserve_context_over_deferred(defer.gatherResults(
            deferreds,
            consumeErrors=True
        )).addErrback(unwrapFirstError)

        if include_none:
            defer.returnValue(valid_pdus)
        else:
            defer.returnValue([p for p in valid_pdus if p])

    def _check_sigs_and_hash(self, pdu):
        return self._check_sigs_and_hashes([pdu])[0]

    def _check_sigs_and_hashes(self, pdus):
        """Throws a SynapseError if a PDU does not have the correct
        signatures.

        Returns:
            FrozenEvent: Either the given event or it redacted if it failed the
            content hash check.
        """

        redacted_pdus = [
            prune_event(pdu)
            for pdu in pdus
        ]

        deferreds = preserve_fn(self.keyring.verify_json_objects_for_server)([
            (p.origin, p.get_pdu_json())
            for p in redacted_pdus
        ])

        def callback(_, pdu, redacted):
            if not check_event_content_hash(pdu):
                logger.warn(
                    "Event content has been tampered, redacting %s: %s",
                    pdu.event_id, pdu.get_pdu_json()
                )
                return redacted
            return pdu

        def errback(failure, pdu):
            failure.trap(SynapseError)
            logger.warn(
                "Signature check failed for %s",
                pdu.event_id,
            )
            return failure

        for deferred, pdu, redacted in zip(deferreds, pdus, redacted_pdus):
            deferred.addCallbacks(
                callback, errback,
                callbackArgs=[pdu, redacted],
                errbackArgs=[pdu],
            )

        return deferreds
