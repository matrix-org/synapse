# Copyright 2014 - 2016 OpenMarket Ltd
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
import typing
from typing import Any, Collection, Dict, Iterable, List, Optional, Set, Tuple, Union

from canonicaljson import encode_canonical_json
from signedjson.key import decode_verify_key_bytes
from signedjson.sign import SignatureVerifyException, verify_signed_json
from typing_extensions import Protocol
from unpaddedbase64 import decode_base64

from synapse.api.constants import (
    MAX_PDU_SIZE,
    EventContentFields,
    EventTypes,
    JoinRules,
    Membership,
)
from synapse.api.errors import (
    AuthError,
    Codes,
    EventSizeError,
    SynapseError,
    UnstableSpecAuthError,
)
from synapse.api.room_versions import (
    KNOWN_ROOM_VERSIONS,
    EventFormatVersions,
    RoomVersion,
)
from synapse.storage.databases.main.events_worker import EventRedactBehaviour
from synapse.types import MutableStateMap, StateMap, UserID, get_domain_from_id

if typing.TYPE_CHECKING:
    # conditional imports to avoid import cycle
    from synapse.events import EventBase
    from synapse.events.builder import EventBuilder

logger = logging.getLogger(__name__)


class _EventSourceStore(Protocol):
    async def get_events(
        self,
        event_ids: Collection[str],
        redact_behaviour: EventRedactBehaviour,
        get_prev_content: bool = False,
        allow_rejected: bool = False,
    ) -> Dict[str, "EventBase"]:
        ...


def validate_event_for_room_version(event: "EventBase") -> None:
    """Ensure that the event complies with the limits, and has the right signatures

    NB: does not *validate* the signatures - it assumes that any signatures present
    have already been checked.

    NB: it does not check that the event satisfies the auth rules (that is done in
    check_auth_rules_for_event) - these tests are independent of the rest of the state
    in the room.

    NB: This is used to check events that have been received over federation. As such,
    it can only enforce the checks specified in the relevant room version, to avoid
    a split-brain situation where some servers accept such events, and others reject
    them. See also EventValidator, which contains extra checks which are applied only to
    locally-generated events.

    Args:
        event: the event to be checked

    Raises:
        SynapseError if there is a problem with the event
    """
    _check_size_limits(event)

    if not hasattr(event, "room_id"):
        raise AuthError(500, "Event has no room_id: %s" % event)

    # check that the event has the correct signatures
    sender_domain = get_domain_from_id(event.sender)

    is_invite_via_3pid = (
        event.type == EventTypes.Member
        and event.membership == Membership.INVITE
        and "third_party_invite" in event.content
    )

    # Check the sender's domain has signed the event
    if not event.signatures.get(sender_domain):
        # We allow invites via 3pid to have a sender from a different
        # HS, as the sender must match the sender of the original
        # 3pid invite. This is checked further down with the
        # other dedicated membership checks.
        if not is_invite_via_3pid:
            raise AuthError(403, "Event not signed by sender's server")

    if event.format_version in (EventFormatVersions.ROOM_V1_V2,):
        # Only older room versions have event IDs to check.
        event_id_domain = get_domain_from_id(event.event_id)

        # Check the origin domain has signed the event
        if not event.signatures.get(event_id_domain):
            raise AuthError(403, "Event not signed by sending server")

    is_invite_via_allow_rule = (
        event.room_version.msc3083_join_rules
        and event.type == EventTypes.Member
        and event.membership == Membership.JOIN
        and EventContentFields.AUTHORISING_USER in event.content
    )
    if is_invite_via_allow_rule:
        authoriser_domain = get_domain_from_id(
            event.content[EventContentFields.AUTHORISING_USER]
        )
        if not event.signatures.get(authoriser_domain):
            raise AuthError(403, "Event not signed by authorising server")


async def check_state_independent_auth_rules(
    store: _EventSourceStore,
    event: "EventBase",
) -> None:
    """Check that an event complies with auth rules that are independent of room state

    Runs through the first few auth rules, which are independent of room state. (Which
    means that we only need to them once for each received event)

    Args:
        store: the datastore; used to fetch the auth events for validation
        event: the event being checked.

    Raises:
        AuthError if the checks fail
    """
    # Implementation of https://spec.matrix.org/v1.2/rooms/v9/#authorization-rules

    # 1. If type is m.room.create:
    if event.type == EventTypes.Create:
        _check_create(event)

        # 1.5 Otherwise, allow
        return

    # 2. Reject if event has auth_events that: ...
    auth_events = await store.get_events(
        event.auth_event_ids(),
        redact_behaviour=EventRedactBehaviour.as_is,
        allow_rejected=True,
    )
    room_id = event.room_id
    auth_dict: MutableStateMap[str] = {}
    expected_auth_types = auth_types_for_event(event.room_version, event)
    for auth_event_id in event.auth_event_ids():
        auth_event = auth_events.get(auth_event_id)

        # we should have all the auth events by now, so if we do not, that suggests
        # a synapse programming error
        if auth_event is None:
            raise RuntimeError(
                f"Event {event.event_id} has unknown auth event {auth_event_id}"
            )

        # We need to ensure that the auth events are actually for the same room, to
        # stop people from using powers they've been granted in other rooms for
        # example.
        if auth_event.room_id != room_id:
            raise AuthError(
                403,
                "During auth for event %s in room %s, found event %s in the state "
                "which is in room %s"
                % (event.event_id, room_id, auth_event_id, auth_event.room_id),
            )

        k = (auth_event.type, auth_event.state_key)

        # 2.1 ... have duplicate entries for a given type and state_key pair
        if k in auth_dict:
            raise AuthError(
                403,
                f"Event {event.event_id} has duplicate auth_events for {k}: {auth_dict[k]} and {auth_event_id}",
            )

        # 2.2 ... have entries whose type and state_key don’t match those specified by
        #   the auth events selection algorithm described in the server
        #   specification.
        if k not in expected_auth_types:
            raise AuthError(
                403,
                f"Event {event.event_id} has unexpected auth_event for {k}: {auth_event_id}",
            )

        # We also need to check that the auth event itself is not rejected.
        if auth_event.rejected_reason:
            raise AuthError(
                403,
                "During auth for event %s: found rejected event %s in the state"
                % (event.event_id, auth_event.event_id),
            )

        auth_dict[k] = auth_event_id

    # 3. If event does not have a m.room.create in its auth_events, reject.
    creation_event = auth_dict.get((EventTypes.Create, ""), None)
    if not creation_event:
        raise AuthError(403, "No create event in auth events")


def check_state_dependent_auth_rules(
    event: "EventBase",
    auth_events: Iterable["EventBase"],
) -> None:
    """Check that an event complies with auth rules that depend on room state

    Runs through the parts of the auth rules that check an event against bits of room
    state.

    Note:

     - it's fine for use in state resolution, when we have already decided whether to
       accept the event or not, and are now trying to decide whether it should make it
       into the room state

     - when we're doing the initial event auth, it is only suitable in combination with
       a bunch of other tests (including, but not limited to, check_state_independent_auth_rules).

    Args:
        event: the event being checked.
        auth_events: the room state to check the events against.

    Raises:
        AuthError if the checks fail
    """
    # there are no state-dependent auth rules for create events.
    if event.type == EventTypes.Create:
        logger.debug("Allowing! %s", event)
        return

    auth_dict = {(e.type, e.state_key): e for e in auth_events}

    # additional check for m.federate
    creating_domain = get_domain_from_id(event.room_id)
    originating_domain = get_domain_from_id(event.sender)
    if creating_domain != originating_domain:
        if not _can_federate(event, auth_dict):
            raise AuthError(403, "This room has been marked as unfederatable.")

    # 4. If type is m.room.aliases
    if (
        event.type == EventTypes.Aliases
        and event.room_version.special_case_aliases_auth
    ):
        # 4a. If event has no state_key, reject
        if not event.is_state():
            raise AuthError(403, "Alias event must be a state event")
        if not event.state_key:
            raise AuthError(403, "Alias event must have non-empty state_key")

        # 4b. If sender's domain doesn't matches [sic] state_key, reject
        sender_domain = get_domain_from_id(event.sender)
        if event.state_key != sender_domain:
            raise AuthError(
                403, "Alias event's state_key does not match sender's domain"
            )

        # 4c. Otherwise, allow.
        logger.debug("Allowing! %s", event)
        return

    # 5. If type is m.room.membership
    if event.type == EventTypes.Member:
        _is_membership_change_allowed(event.room_version, event, auth_dict)
        logger.debug("Allowing! %s", event)
        return

    _check_event_sender_in_room(event, auth_dict)

    # Special case to allow m.room.third_party_invite events wherever
    # a user is allowed to issue invites.  Fixes
    # https://github.com/vector-im/vector-web/issues/1208 hopefully
    if event.type == EventTypes.ThirdPartyInvite:
        user_level = get_user_power_level(event.user_id, auth_dict)
        invite_level = get_named_level(auth_dict, "invite", 0)

        if user_level < invite_level:
            raise UnstableSpecAuthError(
                403,
                "You don't have permission to invite users",
                errcode=Codes.INSUFFICIENT_POWER,
            )
        else:
            logger.debug("Allowing! %s", event)
            return

    _can_send_event(event, auth_dict)

    if event.type == EventTypes.PowerLevels:
        _check_power_levels(event.room_version, event, auth_dict)

    if event.type == EventTypes.Redaction:
        check_redaction(event.room_version, event, auth_dict)

    if (
        event.type == EventTypes.MSC2716_INSERTION
        or event.type == EventTypes.MSC2716_BATCH
        or event.type == EventTypes.MSC2716_MARKER
    ):
        check_historical(event.room_version, event, auth_dict)

    logger.debug("Allowing! %s", event)


def _check_size_limits(event: "EventBase") -> None:
    if len(event.user_id) > 255:
        raise EventSizeError("'user_id' too large")
    if len(event.room_id) > 255:
        raise EventSizeError("'room_id' too large")
    if event.is_state() and len(event.state_key) > 255:
        raise EventSizeError("'state_key' too large")
    if len(event.type) > 255:
        raise EventSizeError("'type' too large")
    if len(event.event_id) > 255:
        raise EventSizeError("'event_id' too large")
    if len(encode_canonical_json(event.get_pdu_json())) > MAX_PDU_SIZE:
        raise EventSizeError("event too large")


def _check_create(event: "EventBase") -> None:
    """Implementation of the auth rules for m.room.create events

    Args:
        event: The `m.room.create` event to be checked

    Raises:
        AuthError if the event does not pass the auth rules
    """
    assert event.type == EventTypes.Create

    #  1.1 If it has any previous events, reject.
    if event.prev_event_ids():
        raise AuthError(403, "Create event has prev events")

    # 1.2 If the domain of the room_id does not match the domain of the sender,
    # reject.
    sender_domain = get_domain_from_id(event.sender)
    room_id_domain = get_domain_from_id(event.room_id)
    if room_id_domain != sender_domain:
        raise AuthError(403, "Creation event's room_id domain does not match sender's")

    # 1.3 If content.room_version is present and is not a recognised version, reject
    room_version_prop = event.content.get("room_version", "1")
    if room_version_prop not in KNOWN_ROOM_VERSIONS:
        raise AuthError(
            403,
            "room appears to have unsupported version %s" % (room_version_prop,),
        )

    # 1.4 If content has no creator field, reject.
    if EventContentFields.ROOM_CREATOR not in event.content:
        raise AuthError(403, "Create event lacks a 'creator' property")


def _can_federate(event: "EventBase", auth_events: StateMap["EventBase"]) -> bool:
    creation_event = auth_events.get((EventTypes.Create, ""))
    # There should always be a creation event, but if not don't federate.
    if not creation_event:
        return False

    return creation_event.content.get(EventContentFields.FEDERATE, True) is True


def _is_membership_change_allowed(
    room_version: RoomVersion, event: "EventBase", auth_events: StateMap["EventBase"]
) -> None:
    """
    Confirms that the event which changes membership is an allowed change.

    Args:
        room_version: The version of the room.
        event: The event to check.
        auth_events: The current auth events of the room.

    Raises:
        AuthError if the event is not allowed.
    """
    membership = event.content["membership"]

    # Check if this is the room creator joining:
    if len(event.prev_event_ids()) == 1 and Membership.JOIN == membership:
        # Get room creation event:
        key = (EventTypes.Create, "")
        create = auth_events.get(key)
        if create and event.prev_event_ids()[0] == create.event_id:
            if create.content["creator"] == event.state_key:
                return

    target_user_id = event.state_key

    creating_domain = get_domain_from_id(event.room_id)
    target_domain = get_domain_from_id(target_user_id)
    if creating_domain != target_domain:
        if not _can_federate(event, auth_events):
            raise AuthError(403, "This room has been marked as unfederatable.")

    # get info about the caller
    key = (EventTypes.Member, event.user_id)
    caller = auth_events.get(key)

    caller_in_room = caller and caller.membership == Membership.JOIN
    caller_invited = caller and caller.membership == Membership.INVITE
    caller_knocked = (
        caller
        and room_version.msc2403_knocking
        and caller.membership == Membership.KNOCK
    )

    # get info about the target
    key = (EventTypes.Member, target_user_id)
    target = auth_events.get(key)

    target_in_room = target and target.membership == Membership.JOIN
    target_banned = target and target.membership == Membership.BAN

    key = (EventTypes.JoinRules, "")
    join_rule_event = auth_events.get(key)
    if join_rule_event:
        join_rule = join_rule_event.content.get("join_rule", JoinRules.INVITE)
    else:
        join_rule = JoinRules.INVITE

    user_level = get_user_power_level(event.user_id, auth_events)
    target_level = get_user_power_level(target_user_id, auth_events)

    invite_level = get_named_level(auth_events, "invite", 0)
    ban_level = get_named_level(auth_events, "ban", 50)

    logger.debug(
        "_is_membership_change_allowed: %s",
        {
            "caller_in_room": caller_in_room,
            "caller_invited": caller_invited,
            "caller_knocked": caller_knocked,
            "target_banned": target_banned,
            "target_in_room": target_in_room,
            "membership": membership,
            "join_rule": join_rule,
            "target_user_id": target_user_id,
            "event.user_id": event.user_id,
        },
    )

    if Membership.INVITE == membership and "third_party_invite" in event.content:
        if not _verify_third_party_invite(event, auth_events):
            raise AuthError(403, "You are not invited to this room.")
        if target_banned:
            raise AuthError(403, "%s is banned from the room" % (target_user_id,))
        return

    # Require the user to be in the room for membership changes other than join/knock.
    # Note that the room version check for knocking is done implicitly by `caller_knocked`
    # and the ability to set a membership of `knock` in the first place.
    if Membership.JOIN != membership and Membership.KNOCK != membership:
        # If the user has been invited or has knocked, they are allowed to change their
        # membership event to leave
        if (
            (caller_invited or caller_knocked)
            and Membership.LEAVE == membership
            and target_user_id == event.user_id
        ):
            return

        if not caller_in_room:  # caller isn't joined
            raise UnstableSpecAuthError(
                403,
                "%s not in room %s." % (event.user_id, event.room_id),
                errcode=Codes.NOT_JOINED,
            )

    if Membership.INVITE == membership:
        # TODO (erikj): We should probably handle this more intelligently
        # PRIVATE join rules.

        # Invites are valid iff caller is in the room and target isn't.
        if target_banned:
            raise AuthError(403, "%s is banned from the room" % (target_user_id,))
        elif target_in_room:  # the target is already in the room.
            raise UnstableSpecAuthError(
                403,
                "%s is already in the room." % target_user_id,
                errcode=Codes.ALREADY_JOINED,
            )
        else:
            if user_level < invite_level:
                raise UnstableSpecAuthError(
                    403,
                    "You don't have permission to invite users",
                    errcode=Codes.INSUFFICIENT_POWER,
                )
    elif Membership.JOIN == membership:
        # Joins are valid iff caller == target and:
        # * They are not banned.
        # * They are accepting a previously sent invitation.
        # * They are already joined (it's a NOOP).
        # * The room is public.
        # * The room is restricted and the user meets the allows rules.
        if event.user_id != target_user_id:
            raise AuthError(403, "Cannot force another user to join.")
        elif target_banned:
            raise AuthError(403, "You are banned from this room")
        elif join_rule == JoinRules.PUBLIC:
            pass
        elif (
            room_version.msc3083_join_rules and join_rule == JoinRules.RESTRICTED
        ) or (
            room_version.msc3787_knock_restricted_join_rule
            and join_rule == JoinRules.KNOCK_RESTRICTED
        ):
            # This is the same as public, but the event must contain a reference
            # to the server who authorised the join. If the event does not contain
            # the proper content it is rejected.
            #
            # Note that if the caller is in the room or invited, then they do
            # not need to meet the allow rules.
            if not caller_in_room and not caller_invited:
                authorising_user = event.content.get(
                    EventContentFields.AUTHORISING_USER
                )

                if authorising_user is None:
                    raise AuthError(403, "Join event is missing authorising user.")

                # The authorising user must be in the room.
                key = (EventTypes.Member, authorising_user)
                member_event = auth_events.get(key)
                _check_joined_room(member_event, authorising_user, event.room_id)

                authorising_user_level = get_user_power_level(
                    authorising_user, auth_events
                )
                if authorising_user_level < invite_level:
                    raise AuthError(403, "Join event authorised by invalid server.")

        elif (
            join_rule == JoinRules.INVITE
            or (room_version.msc2403_knocking and join_rule == JoinRules.KNOCK)
            or (
                room_version.msc3787_knock_restricted_join_rule
                and join_rule == JoinRules.KNOCK_RESTRICTED
            )
        ):
            if not caller_in_room and not caller_invited:
                raise AuthError(403, "You are not invited to this room.")
        else:
            # TODO (erikj): may_join list
            # TODO (erikj): private rooms
            raise AuthError(403, "You are not allowed to join this room")
    elif Membership.LEAVE == membership:
        # TODO (erikj): Implement kicks.
        if target_banned and user_level < ban_level:
            raise UnstableSpecAuthError(
                403,
                "You cannot unban user %s." % (target_user_id,),
                errcode=Codes.INSUFFICIENT_POWER,
            )
        elif target_user_id != event.user_id:
            kick_level = get_named_level(auth_events, "kick", 50)

            if user_level < kick_level or user_level <= target_level:
                raise UnstableSpecAuthError(
                    403,
                    "You cannot kick user %s." % target_user_id,
                    errcode=Codes.INSUFFICIENT_POWER,
                )
    elif Membership.BAN == membership:
        if user_level < ban_level or user_level <= target_level:
            raise UnstableSpecAuthError(
                403,
                "You don't have permission to ban",
                errcode=Codes.INSUFFICIENT_POWER,
            )
    elif room_version.msc2403_knocking and Membership.KNOCK == membership:
        if join_rule != JoinRules.KNOCK and (
            not room_version.msc3787_knock_restricted_join_rule
            or join_rule != JoinRules.KNOCK_RESTRICTED
        ):
            raise AuthError(403, "You don't have permission to knock")
        elif target_user_id != event.user_id:
            raise AuthError(403, "You cannot knock for other users")
        elif target_in_room:
            raise UnstableSpecAuthError(
                403,
                "You cannot knock on a room you are already in",
                errcode=Codes.ALREADY_JOINED,
            )
        elif caller_invited:
            raise AuthError(403, "You are already invited to this room")
        elif target_banned:
            raise AuthError(403, "You are banned from this room")
    else:
        raise AuthError(500, "Unknown membership %s" % membership)


def _check_event_sender_in_room(
    event: "EventBase", auth_events: StateMap["EventBase"]
) -> None:
    key = (EventTypes.Member, event.user_id)
    member_event = auth_events.get(key)

    _check_joined_room(member_event, event.user_id, event.room_id)


def _check_joined_room(
    member: Optional["EventBase"], user_id: str, room_id: str
) -> None:
    if not member or member.membership != Membership.JOIN:
        raise AuthError(
            403, "User %s not in room %s (%s)" % (user_id, room_id, repr(member))
        )


def get_send_level(
    etype: str, state_key: Optional[str], power_levels_event: Optional["EventBase"]
) -> int:
    """Get the power level required to send an event of a given type

    The federation spec [1] refers to this as "Required Power Level".

    https://matrix.org/docs/spec/server_server/unstable.html#definitions

    Args:
        etype: type of event
        state_key: state_key of state event, or None if it is not
            a state event.
        power_levels_event: power levels event
            in force at this point in the room
    Returns:
        power level required to send this event.
    """

    if power_levels_event:
        power_levels_content = power_levels_event.content
    else:
        power_levels_content = {}

    # see if we have a custom level for this event type
    send_level = power_levels_content.get("events", {}).get(etype)

    # otherwise, fall back to the state_default/events_default.
    if send_level is None:
        if state_key is not None:
            send_level = power_levels_content.get("state_default", 50)
        else:
            send_level = power_levels_content.get("events_default", 0)

    return int(send_level)


def _can_send_event(event: "EventBase", auth_events: StateMap["EventBase"]) -> bool:
    power_levels_event = get_power_level_event(auth_events)

    send_level = get_send_level(event.type, event.get("state_key"), power_levels_event)
    user_level = get_user_power_level(event.user_id, auth_events)

    if user_level < send_level:
        raise UnstableSpecAuthError(
            403,
            "You don't have permission to post that to the room. "
            + "user_level (%d) < send_level (%d)" % (user_level, send_level),
            errcode=Codes.INSUFFICIENT_POWER,
        )

    # Check state_key
    if hasattr(event, "state_key"):
        if event.state_key.startswith("@"):
            if event.state_key != event.user_id:
                raise AuthError(403, "You are not allowed to set others state")

    return True


def check_redaction(
    room_version_obj: RoomVersion,
    event: "EventBase",
    auth_events: StateMap["EventBase"],
) -> bool:
    """Check whether the event sender is allowed to redact the target event.

    Returns:
        True if the the sender is allowed to redact the target event if the
        target event was created by them.
        False if the sender is allowed to redact the target event with no
        further checks.

    Raises:
        AuthError if the event sender is definitely not allowed to redact
        the target event.
    """
    user_level = get_user_power_level(event.user_id, auth_events)

    redact_level = get_named_level(auth_events, "redact", 50)

    if user_level >= redact_level:
        return False

    if room_version_obj.event_format == EventFormatVersions.ROOM_V1_V2:
        redacter_domain = get_domain_from_id(event.event_id)
        if not isinstance(event.redacts, str):
            return False
        redactee_domain = get_domain_from_id(event.redacts)
        if redacter_domain == redactee_domain:
            return True
    else:
        event.internal_metadata.recheck_redaction = True
        return True

    raise AuthError(403, "You don't have permission to redact events")


def check_historical(
    room_version_obj: RoomVersion,
    event: "EventBase",
    auth_events: StateMap["EventBase"],
) -> None:
    """Check whether the event sender is allowed to send historical related
    events like "insertion", "batch", and "marker".

    Returns:
        None

    Raises:
        AuthError if the event sender is not allowed to send historical related events
        ("insertion", "batch", and "marker").
    """
    # Ignore the auth checks in room versions that do not support historical
    # events
    if not room_version_obj.msc2716_historical:
        return

    user_level = get_user_power_level(event.user_id, auth_events)

    historical_level = get_named_level(auth_events, "historical", 100)

    if user_level < historical_level:
        raise UnstableSpecAuthError(
            403,
            'You don\'t have permission to send send historical related events ("insertion", "batch", and "marker")',
            errcode=Codes.INSUFFICIENT_POWER,
        )


def _check_power_levels(
    room_version_obj: RoomVersion,
    event: "EventBase",
    auth_events: StateMap["EventBase"],
) -> None:
    user_list = event.content.get("users", {})
    # Validate users
    for k, v in user_list.items():
        try:
            UserID.from_string(k)
        except Exception:
            raise SynapseError(400, "Not a valid user_id: %s" % (k,))

        try:
            int(v)
        except Exception:
            raise SynapseError(400, "Not a valid power level: %s" % (v,))

    # Reject events with stringy power levels if required by room version
    if (
        event.type == EventTypes.PowerLevels
        and room_version_obj.msc3667_int_only_power_levels
    ):
        for k, v in event.content.items():
            if k in {
                "users_default",
                "events_default",
                "state_default",
                "ban",
                "redact",
                "kick",
                "invite",
            }:
                if not isinstance(v, int):
                    raise SynapseError(400, f"{v!r} must be an integer.")
            if k in {"events", "notifications", "users"}:
                if not isinstance(v, dict) or not all(
                    isinstance(v, int) for v in v.values()
                ):
                    raise SynapseError(
                        400,
                        f"{v!r} must be a dict wherein all the values are integers.",
                    )

    key = (event.type, event.state_key)
    current_state = auth_events.get(key)

    if not current_state:
        return

    user_level = get_user_power_level(event.user_id, auth_events)

    # Check other levels:
    levels_to_check: List[Tuple[str, Optional[str]]] = [
        ("users_default", None),
        ("events_default", None),
        ("state_default", None),
        ("ban", None),
        ("redact", None),
        ("kick", None),
        ("invite", None),
    ]

    old_list = current_state.content.get("users", {})
    for user in set(list(old_list) + list(user_list)):
        levels_to_check.append((user, "users"))

    old_list = current_state.content.get("events", {})
    new_list = event.content.get("events", {})
    for ev_id in set(list(old_list) + list(new_list)):
        levels_to_check.append((ev_id, "events"))

    # MSC2209 specifies these checks should also be done for the "notifications"
    # key.
    if room_version_obj.limit_notifications_power_levels:
        old_list = current_state.content.get("notifications", {})
        new_list = event.content.get("notifications", {})
        for ev_id in set(list(old_list) + list(new_list)):
            levels_to_check.append((ev_id, "notifications"))

    old_state = current_state.content
    new_state = event.content

    for level_to_check, dir in levels_to_check:
        old_loc = old_state
        new_loc = new_state
        if dir:
            old_loc = old_loc.get(dir, {})
            new_loc = new_loc.get(dir, {})

        if level_to_check in old_loc:
            old_level: Optional[int] = int(old_loc[level_to_check])
        else:
            old_level = None

        if level_to_check in new_loc:
            new_level: Optional[int] = int(new_loc[level_to_check])
        else:
            new_level = None

        if new_level is not None and old_level is not None:
            if new_level == old_level:
                continue

        if dir == "users" and level_to_check != event.user_id:
            if old_level == user_level:
                raise AuthError(
                    403,
                    "You don't have permission to remove ops level equal "
                    "to your own",
                )

        # Check if the old and new levels are greater than the user level
        # (if defined)
        old_level_too_big = old_level is not None and old_level > user_level
        new_level_too_big = new_level is not None and new_level > user_level
        if old_level_too_big or new_level_too_big:
            raise AuthError(
                403, "You don't have permission to add ops level greater than your own"
            )


def get_power_level_event(auth_events: StateMap["EventBase"]) -> Optional["EventBase"]:
    return auth_events.get((EventTypes.PowerLevels, ""))


def get_user_power_level(user_id: str, auth_events: StateMap["EventBase"]) -> int:
    """Get a user's power level

    Args:
        user_id: user's id to look up in power_levels
        auth_events:
            state in force at this point in the room (or rather, a subset of
            it including at least the create event and power levels event.

    Returns:
        the user's power level in this room.
    """
    power_level_event = get_power_level_event(auth_events)
    if power_level_event:
        level = power_level_event.content.get("users", {}).get(user_id)
        if level is None:
            level = power_level_event.content.get("users_default", 0)

        if level is None:
            return 0
        else:
            return int(level)
    else:
        # if there is no power levels event, the creator gets 100 and everyone
        # else gets 0.

        # some things which call this don't pass the create event: hack around
        # that.
        key = (EventTypes.Create, "")
        create_event = auth_events.get(key)
        if create_event is not None and create_event.content["creator"] == user_id:
            return 100
        else:
            return 0


def get_named_level(auth_events: StateMap["EventBase"], name: str, default: int) -> int:
    power_level_event = get_power_level_event(auth_events)

    if not power_level_event:
        return default

    level = power_level_event.content.get(name, None)
    if level is not None:
        return int(level)
    else:
        return default


def _verify_third_party_invite(
    event: "EventBase", auth_events: StateMap["EventBase"]
) -> bool:
    """
    Validates that the invite event is authorized by a previous third-party invite.

    Checks that the public key, and keyserver, match those in the third party invite,
    and that the invite event has a signature issued using that public key.

    Args:
        event: The m.room.member join event being validated.
        auth_events: All relevant previous context events which may be used
            for authorization decisions.

    Return:
        True if the event fulfills the expectations of a previous third party
        invite event.
    """
    if "third_party_invite" not in event.content:
        return False
    if "signed" not in event.content["third_party_invite"]:
        return False
    signed = event.content["third_party_invite"]["signed"]
    for key in {"mxid", "token"}:
        if key not in signed:
            return False

    token = signed["token"]

    invite_event = auth_events.get((EventTypes.ThirdPartyInvite, token))
    if not invite_event:
        return False

    if invite_event.sender != event.sender:
        return False

    if event.user_id != invite_event.user_id:
        return False

    if signed["mxid"] != event.state_key:
        return False
    if signed["token"] != token:
        return False

    for public_key_object in get_public_keys(invite_event):
        public_key = public_key_object["public_key"]
        try:
            for server, signature_block in signed["signatures"].items():
                for key_name in signature_block.keys():
                    if not key_name.startswith("ed25519:"):
                        continue
                    verify_key = decode_verify_key_bytes(
                        key_name, decode_base64(public_key)
                    )
                    verify_signed_json(signed, server, verify_key)

                    # We got the public key from the invite, so we know that the
                    # correct server signed the signed bundle.
                    # The caller is responsible for checking that the signing
                    # server has not revoked that public key.
                    return True
        except (KeyError, SignatureVerifyException):
            continue
    return False


def get_public_keys(invite_event: "EventBase") -> List[Dict[str, Any]]:
    public_keys = []
    if "public_key" in invite_event.content:
        o = {"public_key": invite_event.content["public_key"]}
        if "key_validity_url" in invite_event.content:
            o["key_validity_url"] = invite_event.content["key_validity_url"]
        public_keys.append(o)
    public_keys.extend(invite_event.content.get("public_keys", []))
    return public_keys


def auth_types_for_event(
    room_version: RoomVersion, event: Union["EventBase", "EventBuilder"]
) -> Set[Tuple[str, str]]:
    """Given an event, return a list of (EventType, StateKey) that may be
    needed to auth the event. The returned list may be a superset of what
    would actually be required depending on the full state of the room.

    Used to limit the number of events to fetch from the database to
    actually auth the event.
    """
    if event.type == EventTypes.Create:
        return set()

    auth_types = {
        (EventTypes.PowerLevels, ""),
        (EventTypes.Member, event.sender),
        (EventTypes.Create, ""),
    }

    if event.type == EventTypes.Member:
        membership = event.content["membership"]
        if membership in [Membership.JOIN, Membership.INVITE, Membership.KNOCK]:
            auth_types.add((EventTypes.JoinRules, ""))

        auth_types.add((EventTypes.Member, event.state_key))

        if membership == Membership.INVITE:
            if "third_party_invite" in event.content:
                key = (
                    EventTypes.ThirdPartyInvite,
                    event.content["third_party_invite"]["signed"]["token"],
                )
                auth_types.add(key)

        if room_version.msc3083_join_rules and membership == Membership.JOIN:
            if EventContentFields.AUTHORISING_USER in event.content:
                key = (
                    EventTypes.Member,
                    event.content[EventContentFields.AUTHORISING_USER],
                )
                auth_types.add(key)

    return auth_types
