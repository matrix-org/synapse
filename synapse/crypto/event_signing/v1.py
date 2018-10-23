# -*- coding: utf-8 -*-

# Copyright 2014-2016 OpenMarket Ltd
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


import hashlib
import logging

from canonicaljson import encode_canonical_json
from signedjson.sign import sign_json
from unpaddedbase64 import decode_base64, encode_base64

from synapse.api.errors import Codes, SynapseError
from synapse.events.utils import prune_event

logger = logging.getLogger(__name__)


def check_event_content_hash(event, hash_algorithm=hashlib.sha256):
    """Check whether the hash for this PDU matches the contents

    Args:
        event (EventBase)
        hash_algorithm (hashlib.hash)
        room_version (RoomVersions)

    Returns
        bool
    """
    name, expected_hash = _compute_content_hash(event, hash_algorithm)
    logger.debug("Expecting hash: %s", encode_base64(expected_hash))

    # some malformed events lack a 'hashes'. Protect against it being missing
    # or a weird type by basically treating it the same as an unhashed event.
    hashes = event.get("hashes")
    if not isinstance(hashes, dict):
        raise SynapseError(400, "Malformed 'hashes'", Codes.UNAUTHORIZED)

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


def _compute_content_hash(event, hash_algorithm):
    event_json = event.get_pdu_json()
    event_json.pop("age_ts", None)
    event_json.pop("unsigned", None)
    event_json.pop("signatures", None)
    event_json.pop("hashes", None)
    event_json.pop("outlier", None)
    event_json.pop("destinations", None)

    event_json_bytes = encode_canonical_json(event_json)

    hashed = hash_algorithm(event_json_bytes)
    return (hashed.name, hashed.digest())


def compute_event_reference_hash(event, hash_algorithm=hashlib.sha256):
    """Compute the event reference hash

    Args:
        event (EventBase)
        hash_algorithm (hashlib.hash)
        room_version (RoomVersions)

    Returns
        tuple[str, bytes]: Tuple of hash name and digest bytes
    """
    tmp_event = prune_event(event)
    event_json = tmp_event.get_pdu_json()
    event_json.pop("signatures", None)
    event_json.pop("age_ts", None)
    event_json.pop("unsigned", None)
    event_json_bytes = encode_canonical_json(event_json)
    hashed = hash_algorithm(event_json_bytes)
    return (hashed.name, hashed.digest())


def compute_event_signature(event, signature_name, signing_key):
    """Returns signature for the event with given name and key.

    Args:
        event (EventBase)
        signature_name (str): The name of the entity signing, usually the
            server name.
        signing_key: A signing key for the entity, as returned by `signedjson`
        room_version (RoomVersions)

    Returns:
        dict[str, dict[str, str]]: Dictionary that contains the event
        signature. Maps from entity name to key ID to base64 encoded signature.
    """
    tmp_event = prune_event(event)
    redact_json = tmp_event.get_pdu_json()
    redact_json.pop("age_ts", None)
    redact_json.pop("unsigned", None)
    logger.debug("Signing event: %s", encode_canonical_json(redact_json))
    redact_json = sign_json(redact_json, signature_name, signing_key)
    logger.debug("Signed event: %s", encode_canonical_json(redact_json))
    return redact_json["signatures"]


def add_hashes_and_signatures(
    event, signature_name, signing_key, hash_algorithm=hashlib.sha256
):
    """Adds content hash and signature to the event

    Args:
        event (EventBuilder)
        signature_name (str): The name of the entity signing, usually the
            server name.
        signing_key: A signing key for the entity, as returned by `signedjson`
        hash_algorithm (hashlib.hash)
        room_version (RoomVersions)
    """

    name, digest = _compute_content_hash(event, hash_algorithm=hash_algorithm)

    if not hasattr(event, "hashes"):
        event.hashes = {}
    event.hashes[name] = encode_base64(digest)

    event.signatures = compute_event_signature(
        event, signature_name=signature_name, signing_key=signing_key
    )
