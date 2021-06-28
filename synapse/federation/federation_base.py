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

from synapse.api.constants import MAX_DEPTH, EventTypes, Membership
from synapse.api.errors import Codes, SynapseError
from synapse.api.room_versions import EventFormatVersions, RoomVersion
from synapse.crypto.event_signing import check_event_content_hash
from synapse.crypto.keyring import Keyring
from synapse.events import EventBase, make_event_from_dict
from synapse.events.utils import prune_event, validate_canonicaljson
from synapse.http.servlet import assert_params_in_dict
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

    async def _check_sigs_and_hash(
        self, room_version: RoomVersion, pdu: EventBase
    ) -> EventBase:
        """Checks that event is correctly signed by the sending server.

        Args:
            room_version: The room version of the PDU
            pdu: the event to be checked

        Returns:
              * the original event if the checks pass
              * a redacted version of the event (if the signature
                matched but the hash did not)
              * throws a SynapseError if the signature check failed."""
        try:
            await _check_sigs_on_pdu(self.keyring, room_version, pdu)
        except SynapseError as e:
            logger.warning(
                "Signature check failed for %s: %s",
                pdu.event_id,
                e,
            )
            raise

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
                    "Event %s seems to have been redacted; using our redacted copy",
                    pdu.event_id,
                )
            else:
                logger.warning(
                    "Event %s content has been tampered, redacting",
                    pdu.event_id,
                )
            return redacted_event

        result = await self.spam_checker.check_event_for_spam(pdu)

        if result:
            logger.warning("Event contains spam, soft-failing %s", pdu.event_id)
            # we redact (to save disk space) as well as soft-failing (to stop
            # using the event in prev_events).
            redacted_event = prune_event(pdu)
            redacted_event.internal_metadata.soft_failed = True
            return redacted_event

        return pdu


class PduToCheckSig(namedtuple("PduToCheckSig", ["pdu", "sender_domain", "deferreds"])):
    pass


async def _check_sigs_on_pdu(
    keyring: Keyring, room_version: RoomVersion, pdu: EventBase
) -> None:
    """Check that the given events are correctly signed

    Raise a SynapseError if the event wasn't correctly signed.

    Args:
        keyring: keyring object to do the checks
        room_version: the room version of the PDUs
        pdus: the events to be checked
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

    # First we check that the sender event is signed by the sender's domain
    # (except if its a 3pid invite, in which case it may be sent by any server)
    if not _is_invite_via_3pid(pdu):
        try:
            await keyring.verify_event_for_server(
                get_domain_from_id(pdu.sender),
                pdu,
                pdu.origin_server_ts if room_version.enforce_key_validity else 0,
            )
        except Exception as e:
            errmsg = "event id %s: unable to verify signature for sender %s: %s" % (
                pdu.event_id,
                get_domain_from_id(pdu.sender),
                e,
            )
            raise SynapseError(403, errmsg, Codes.FORBIDDEN)

    # now let's look for events where the sender's domain is different to the
    # event id's domain (normally only the case for joins/leaves), and add additional
    # checks. Only do this if the room version has a concept of event ID domain
    # (ie, the room version uses old-style non-hash event IDs).
    if room_version.event_format == EventFormatVersions.V1 and get_domain_from_id(
        pdu.event_id
    ) != get_domain_from_id(pdu.sender):
        try:
            await keyring.verify_event_for_server(
                get_domain_from_id(pdu.event_id),
                pdu,
                pdu.origin_server_ts if room_version.enforce_key_validity else 0,
            )
        except Exception as e:
            errmsg = (
                "event id %s: unable to verify signature for event id domain %s: %s"
                % (
                    pdu.event_id,
                    get_domain_from_id(pdu.event_id),
                    e,
                )
            )
            raise SynapseError(403, errmsg, Codes.FORBIDDEN)


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
