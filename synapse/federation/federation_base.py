# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2020 The Matrix.org Foundation C.I.C.
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
from collections import namedtuple
from typing import Iterable, List

from twisted.internet import defer
from twisted.internet.defer import Deferred, DeferredList
from twisted.python.failure import Failure

from synapse.api.constants import MAX_DEPTH, EventTypes, Membership
from synapse.api.errors import Codes, SynapseError
from synapse.api.room_versions import EventFormatVersions, RoomVersion
from synapse.crypto.event_signing import check_event_content_hash
from synapse.crypto.keyring import Keyring
from synapse.events import EventBase, make_event_from_dict
from synapse.events.utils import prune_event, validate_canonicaljson
from synapse.http.servlet import assert_params_in_dict
from synapse.logging.context import (
    PreserveLoggingContext,
    current_context,
    make_deferred_yieldable,
)
from synapse.types import JsonDict, get_domain_from_id

logger = logging.getLogger(__name__)


class FederationBase:
    def __init__(self, hs):
        self.hs = hs

        self.server_name = hs.hostname
        self.keyring = hs.get_keyring()
        self.spam_checker = hs.get_spam_checker()
        self.store = hs.get_datastore()
        self._clock = hs.get_clock()

    def _check_sigs_and_hash(
        self, room_version: RoomVersion, pdu: EventBase
    ) -> Deferred:
        return make_deferred_yieldable(
            self._check_sigs_and_hashes(room_version, [pdu])[0]
        )

    def _check_sigs_and_hashes(
        self, room_version: RoomVersion, pdus: List[EventBase]
    ) -> List[Deferred]:
        """Checks that each of the received events is correctly signed by the
        sending server.

        Args:
            room_version: The room version of the PDUs
            pdus: the events to be checked

        Returns:
            For each input event, a deferred which:
              * returns the original event if the checks pass
              * returns a redacted version of the event (if the signature
                matched but the hash did not)
              * throws a SynapseError if the signature check failed.
            The deferreds run their callbacks in the sentinel
        """
        deferreds = _check_sigs_on_pdus(self.keyring, room_version, pdus)

        ctx = current_context()

        @defer.inlineCallbacks
        def callback(_, pdu: EventBase):
            with PreserveLoggingContext(ctx):
                if not check_event_content_hash(pdu):
                    # let's try to distinguish between failures because the event was
                    # redacted (which are somewhat expected) vs actual ball-tampering
                    # incidents.
                    #
                    # This is just a heuristic, so we just assume that if the keys are
                    # about the same between the redacted and received events, then the
                    # received event was probably a redacted copy (but we then use our
                    # *actual* redacted copy to be on the safe side.)
                    redacted_event = prune_event(pdu)
                    if set(redacted_event.keys()) == set(pdu.keys()) and set(
                        redacted_event.content.keys()
                    ) == set(pdu.content.keys()):
                        logger.info(
                            "Event %s seems to have been redacted; using our redacted "
                            "copy",
                            pdu.event_id,
                        )
                    else:
                        logger.warning(
                            "Event %s content has been tampered, redacting",
                            pdu.event_id,
                        )
                    return redacted_event

                result = yield defer.ensureDeferred(
                    self.spam_checker.check_event_for_spam(pdu)
                )

                if result:
                    logger.warning(
                        "Event contains spam, redacting %s: %s",
                        pdu.event_id,
                        pdu.get_pdu_json(),
                    )
                    return prune_event(pdu)

                return pdu

        def errback(failure: Failure, pdu: EventBase):
            failure.trap(SynapseError)
            with PreserveLoggingContext(ctx):
                logger.warning(
                    "Signature check failed for %s: %s",
                    pdu.event_id,
                    failure.getErrorMessage(),
                )
            return failure

        for deferred, pdu in zip(deferreds, pdus):
            deferred.addCallbacks(
                callback, errback, callbackArgs=[pdu], errbackArgs=[pdu]
            )

        return deferreds


class PduToCheckSig(namedtuple("PduToCheckSig", ["pdu", "sender_domain", "deferreds"])):
    pass


def _check_sigs_on_pdus(
    keyring: Keyring, room_version: RoomVersion, pdus: Iterable[EventBase]
) -> List[Deferred]:
    """Check that the given events are correctly signed

    Args:
        keyring: keyring object to do the checks
        room_version: the room version of the PDUs
        pdus: the events to be checked

    Returns:
        A Deferred for each event in pdus, which will either succeed if
           the signatures are valid, or fail (with a SynapseError) if not.
    """

    # we want to check that the event is signed by:
    #
    # (a) the sender's server
    #
    #     - except in the case of invites created from a 3pid invite, which are exempt
    #     from this check, because the sender has to match that of the original 3pid
    #     invite, but the event may come from a different HS, for reasons that I don't
    #     entirely grok (why do the senders have to match? and if they do, why doesn't the
    #     joining server ask the inviting server to do the switcheroo with
    #     exchange_third_party_invite?).
    #
    #     That's pretty awful, since redacting such an invite will render it invalid
    #     (because it will then look like a regular invite without a valid signature),
    #     and signatures are *supposed* to be valid whether or not an event has been
    #     redacted. But this isn't the worst of the ways that 3pid invites are broken.
    #
    # (b) for V1 and V2 rooms, the server which created the event_id
    #
    # let's start by getting the domain for each pdu, and flattening the event back
    # to JSON.

    pdus_to_check = [
        PduToCheckSig(
            pdu=p,
            sender_domain=get_domain_from_id(p.sender),
            deferreds=[],
        )
        for p in pdus
    ]

    # First we check that the sender event is signed by the sender's domain
    # (except if its a 3pid invite, in which case it may be sent by any server)
    pdus_to_check_sender = [p for p in pdus_to_check if not _is_invite_via_3pid(p.pdu)]

    more_deferreds = keyring.verify_events_for_server(
        [
            (
                p.sender_domain,
                p.pdu,
                p.pdu.origin_server_ts if room_version.enforce_key_validity else 0,
            )
            for p in pdus_to_check_sender
        ]
    )

    def sender_err(e, pdu_to_check):
        errmsg = "event id %s: unable to verify signature for sender %s: %s" % (
            pdu_to_check.pdu.event_id,
            pdu_to_check.sender_domain,
            e.getErrorMessage(),
        )
        raise SynapseError(403, errmsg, Codes.FORBIDDEN)

    for p, d in zip(pdus_to_check_sender, more_deferreds):
        d.addErrback(sender_err, p)
        p.deferreds.append(d)

    # now let's look for events where the sender's domain is different to the
    # event id's domain (normally only the case for joins/leaves), and add additional
    # checks. Only do this if the room version has a concept of event ID domain
    # (ie, the room version uses old-style non-hash event IDs).
    if room_version.event_format == EventFormatVersions.V1:
        pdus_to_check_event_id = [
            p
            for p in pdus_to_check
            if p.sender_domain != get_domain_from_id(p.pdu.event_id)
        ]

        more_deferreds = keyring.verify_events_for_server(
            [
                (
                    get_domain_from_id(p.pdu.event_id),
                    p.pdu,
                    p.pdu.origin_server_ts if room_version.enforce_key_validity else 0,
                )
                for p in pdus_to_check_event_id
            ]
        )

        def event_err(e, pdu_to_check):
            errmsg = (
                "event id %s: unable to verify signature for event id domain: %s"
                % (pdu_to_check.pdu.event_id, e.getErrorMessage())
            )
            raise SynapseError(403, errmsg, Codes.FORBIDDEN)

        for p, d in zip(pdus_to_check_event_id, more_deferreds):
            d.addErrback(event_err, p)
            p.deferreds.append(d)

    # replace lists of deferreds with single Deferreds
    return [_flatten_deferred_list(p.deferreds) for p in pdus_to_check]


def _flatten_deferred_list(deferreds: List[Deferred]) -> Deferred:
    """Given a list of deferreds, either return the single deferred,
    combine into a DeferredList, or return an already resolved deferred.
    """
    if len(deferreds) > 1:
        return DeferredList(deferreds, fireOnOneErrback=True, consumeErrors=True)
    elif len(deferreds) == 1:
        return deferreds[0]
    else:
        return defer.succeed(None)


def _is_invite_via_3pid(event: EventBase) -> bool:
    return (
        event.type == EventTypes.Member
        and event.membership == Membership.INVITE
        and "third_party_invite" in event.content
    )


def event_from_pdu_json(
    pdu_json: JsonDict, room_version: RoomVersion, outlier: bool = False
) -> EventBase:
    """Construct an EventBase from an event json received over federation

    Args:
        pdu_json: pdu as received over federation
        room_version: The version of the room this event belongs to
        outlier: True to mark this event as an outlier

    Raises:
        SynapseError: if the pdu is missing required fields or is otherwise
            not a valid matrix event
    """
    # we could probably enforce a bunch of other fields here (room_id, sender,
    # origin, etc etc)
    assert_params_in_dict(pdu_json, ("type", "depth"))

    depth = pdu_json["depth"]
    if not isinstance(depth, int):
        raise SynapseError(400, "Depth %r not an intger" % (depth,), Codes.BAD_JSON)

    if depth < 0:
        raise SynapseError(400, "Depth too small", Codes.BAD_JSON)
    elif depth > MAX_DEPTH:
        raise SynapseError(400, "Depth too large", Codes.BAD_JSON)

    # Validate that the JSON conforms to the specification.
    if room_version.strict_canonicaljson:
        validate_canonicaljson(pdu_json)

    event = make_event_from_dict(pdu_json, room_version)
    event.internal_metadata.outlier = outlier

    return event
