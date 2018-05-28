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
import logging

import six

from synapse.api.constants import MAX_DEPTH
from synapse.api.errors import SynapseError, Codes
from synapse.crypto.event_signing import check_event_content_hash
from synapse.events import FrozenEvent
from synapse.events.utils import prune_event
from synapse.http.servlet import assert_params_in_request
from synapse.util import unwrapFirstError, logcontext
from twisted.internet import defer

logger = logging.getLogger(__name__)


class FederationBase(object):
    def __init__(self, hs):
        self.hs = hs

        self.server_name = hs.hostname
        self.keyring = hs.get_keyring()
        self.spam_checker = hs.get_spam_checker()
        self.store = hs.get_datastore()
        self._clock = hs.get_clock()

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

        @defer.inlineCallbacks
        def handle_check_result(pdu, deferred):
            try:
                res = yield logcontext.make_deferred_yieldable(deferred)
            except SynapseError:
                res = None

            if not res:
                # Check local db.
                res = yield self.store.get_event(
                    pdu.event_id,
                    allow_rejected=True,
                    allow_none=True,
                )

            if not res and pdu.origin != origin:
                try:
                    res = yield self.get_pdu(
                        destinations=[pdu.origin],
                        event_id=pdu.event_id,
                        outlier=outlier,
                        timeout=10000,
                    )
                except SynapseError:
                    pass

            if not res:
                logger.warn(
                    "Failed to find copy of %s with valid signature",
                    pdu.event_id,
                )

            defer.returnValue(res)

        handle = logcontext.preserve_fn(handle_check_result)
        deferreds2 = [
            handle(pdu, deferred)
            for pdu, deferred in zip(pdus, deferreds)
        ]

        valid_pdus = yield logcontext.make_deferred_yieldable(
            defer.gatherResults(
                deferreds2,
                consumeErrors=True,
            )
        ).addErrback(unwrapFirstError)

        if include_none:
            defer.returnValue(valid_pdus)
        else:
            defer.returnValue([p for p in valid_pdus if p])

    def _check_sigs_and_hash(self, pdu):
        return logcontext.make_deferred_yieldable(
            self._check_sigs_and_hashes([pdu])[0],
        )

    def _check_sigs_and_hashes(self, pdus):
        """Checks that each of the received events is correctly signed by the
        sending server.

        Args:
            pdus (list[FrozenEvent]): the events to be checked

        Returns:
            list[Deferred]: for each input event, a deferred which:
              * returns the original event if the checks pass
              * returns a redacted version of the event (if the signature
                matched but the hash did not)
              * throws a SynapseError if the signature check failed.
            The deferreds run their callbacks in the sentinel logcontext.
        """

        redacted_pdus = [
            prune_event(pdu)
            for pdu in pdus
        ]

        deferreds = self.keyring.verify_json_objects_for_server([
            (p.origin, p.get_pdu_json())
            for p in redacted_pdus
        ])

        ctx = logcontext.LoggingContext.current_context()

        def callback(_, pdu, redacted):
            with logcontext.PreserveLoggingContext(ctx):
                if not check_event_content_hash(pdu):
                    logger.warn(
                        "Event content has been tampered, redacting %s: %s",
                        pdu.event_id, pdu.get_pdu_json()
                    )
                    return redacted

                if self.spam_checker.check_event_for_spam(pdu):
                    logger.warn(
                        "Event contains spam, redacting %s: %s",
                        pdu.event_id, pdu.get_pdu_json()
                    )
                    return redacted

                return pdu

        def errback(failure, pdu):
            failure.trap(SynapseError)
            with logcontext.PreserveLoggingContext(ctx):
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


def event_from_pdu_json(pdu_json, outlier=False):
    """Construct a FrozenEvent from an event json received over federation

    Args:
        pdu_json (object): pdu as received over federation
        outlier (bool): True to mark this event as an outlier

    Returns:
        FrozenEvent

    Raises:
        SynapseError: if the pdu is missing required fields or is otherwise
            not a valid matrix event
    """
    # we could probably enforce a bunch of other fields here (room_id, sender,
    # origin, etc etc)
    assert_params_in_request(pdu_json, ('event_id', 'type', 'depth'))

    depth = pdu_json['depth']
    if not isinstance(depth, six.integer_types):
        raise SynapseError(400, "Depth %r not an intger" % (depth, ),
                           Codes.BAD_JSON)

    if depth < 0:
        raise SynapseError(400, "Depth too small", Codes.BAD_JSON)
    elif depth > MAX_DEPTH:
        raise SynapseError(400, "Depth too large", Codes.BAD_JSON)

    event = FrozenEvent(
        pdu_json
    )

    event.internal_metadata.outlier = outlier

    return event
