#
# Copyright 2014-2016 OpenMarket Ltd
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

import collections.abc
import hashlib
import logging
from typing import Any, Callable, Dict, Tuple

from canonicaljson import encode_canonical_json
from signedjson.sign import sign_json
from signedjson.types import SigningKey
from unpaddedbase64 import decode_base64, encode_base64

from synapse.api.errors import Codes, SynapseError
from synapse.api.room_versions import RoomVersion
from synapse.events import EventBase
from synapse.events.utils import prune_event, prune_event_dict
from synapse.types import JsonDict

logger = logging.getLogger(__name__)

Hasher = Callable[[bytes], "hashlib._Hash"]


def check_event_content_hash(
    event: EventBase, hash_algorithm: Hasher = hashlib.sha256
) -> bool:
    """Check whether the hash for this PDU matches the contents"""
    name, expected_hash = compute_content_hash(event.get_pdu_json(), hash_algorithm)
    logger.debug(
        "Verifying content hash on %s (expecting: %s)",
        event.event_id,
        encode_base64(expected_hash),
    )

    # some malformed events lack a 'hashes'. Protect against it being missing
    # or a weird type by basically treating it the same as an unhashed event.
    hashes = event.get("hashes")
    # nb it might be a frozendict or a dict
    if not isinstance(hashes, collections.abc.Mapping):
        raise SynapseError(
            400, "Malformed 'hashes': %s" % (type(hashes),), Codes.UNAUTHORIZED
        )

    if name not in hashes:
        raise SynapseError(
            400,
            "Algorithm %s not in hashes %s" % (name, list(hashes)),
            Codes.UNAUTHORIZED,
        )
    message_hash_base64 = hashes[name]
    try:
        message_hash_bytes = decode_base64(message_hash_base64)
    except Exception:
        raise SynapseError(
            400, "Invalid base64: %s" % (message_hash_base64,), Codes.UNAUTHORIZED
        )
    return message_hash_bytes == expected_hash


def compute_content_hash(
    event_dict: Dict[str, Any], hash_algorithm: Hasher
) -> Tuple[str, bytes]:
    """Compute the content hash of an event, which is the hash of the
    unredacted event.

    Args:
        event_dict: The unredacted event as a dict
        hash_algorithm: A hasher from `hashlib`, e.g. hashlib.sha256, to use
            to hash the event

    Returns:
        A tuple of the name of hash and the hash as raw bytes.
    """
    event_dict = dict(event_dict)
    event_dict.pop("age_ts", None)
    event_dict.pop("unsigned", None)
    event_dict.pop("signatures", None)
    event_dict.pop("hashes", None)
    event_dict.pop("outlier", None)
    event_dict.pop("destinations", None)

    event_json_bytes = encode_canonical_json(event_dict)

    hashed = hash_algorithm(event_json_bytes)
    return hashed.name, hashed.digest()


def compute_event_reference_hash(
    event: EventBase, hash_algorithm: Hasher = hashlib.sha256
) -> Tuple[str, bytes]:
    """Computes the event reference hash. This is the hash of the redacted
    event.

    Args:
        event
        hash_algorithm: A hasher from `hashlib`, e.g. hashlib.sha256, to use
            to hash the event

    Returns:
        A tuple of the name of hash and the hash as raw bytes.
    """
    tmp_event = prune_event(event)
    event_dict = tmp_event.get_pdu_json()
    event_dict.pop("signatures", None)
    event_dict.pop("age_ts", None)
    event_dict.pop("unsigned", None)
    event_json_bytes = encode_canonical_json(event_dict)
    hashed = hash_algorithm(event_json_bytes)
    return hashed.name, hashed.digest()


def compute_event_signature(
    room_version: RoomVersion,
    event_dict: JsonDict,
    signature_name: str,
    signing_key: SigningKey,
) -> Dict[str, Dict[str, str]]:
    """Compute the signature of the event for the given name and key.

    Args:
        room_version: the version of the room that this event is in.
            (the room version determines the redaction algorithm and hence the
            json to be signed)

        event_dict: The event as a dict

        signature_name: The name of the entity signing the event
            (typically the server's hostname).

        signing_key: The key to sign with

    Returns:
        a dictionary in the same format of an event's signatures field.
    """
    redact_json = prune_event_dict(room_version, event_dict)
    redact_json.pop("age_ts", None)
    redact_json.pop("unsigned", None)
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("Signing event: %s", encode_canonical_json(redact_json))
    redact_json = sign_json(redact_json, signature_name, signing_key)
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("Signed event: %s", encode_canonical_json(redact_json))
    return redact_json["signatures"]


def add_hashes_and_signatures(
    room_version: RoomVersion,
    event_dict: JsonDict,
    signature_name: str,
    signing_key: SigningKey,
) -> None:
    """Add content hash and sign the event

    Args:
        room_version: the version of the room this event is in

        event_dict: The event to add hashes to and sign
        signature_name: The name of the entity signing the event
            (typically the server's hostname).
        signing_key: The key to sign with
    """

    name, digest = compute_content_hash(event_dict, hash_algorithm=hashlib.sha256)

    event_dict.setdefault("hashes", {})[name] = encode_base64(digest)

    event_dict["signatures"] = compute_event_signature(
        room_version, event_dict, signature_name=signature_name, signing_key=signing_key
    )
