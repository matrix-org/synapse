# -*- coding: utf-8 -*-

# Copyright 2018 New Vector Ltd
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

from synapse.api.constants import RoomVersions
from synapse.crypto.event_signing import v1


def check_event_content_hash(
    event, hash_algorithm=hashlib.sha256, room_version=RoomVersions.V1
):
    """Check whether the hash for this PDU matches the contents

    Args:
        event (EventBase)
        hash_algorithm (hashlib.hash)
        room_version (RoomVersions)

    Returns
        bool
    """
    return v1.check_event_content_hash(event, hash_algorithm)


def compute_event_reference_hash(
    event, hash_algorithm=hashlib.sha256, room_version=RoomVersions.V1
):
    """Compute the event reference hash

    Args:
        event (EventBase)
        hash_algorithm (hashlib.hash)
        room_version (RoomVersions)

    Returns
        tuple[str, bytes]: Tuple of hash name and digest bytes
    """
    return v1.compute_event_reference_hash(event, hash_algorithm)


def compute_event_signature(event, signature_name, signing_key,
                            room_version=RoomVersions.V1):
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
    return v1.compute_event_signature(
        event, signature_name, signing_key,
    )


def add_hashes_and_signatures(
    event,
    signature_name,
    signing_key,
    hash_algorithm=hashlib.sha256,
    room_version=RoomVersions.V1,
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
    return v1.add_hashes_and_signatures(
        event, signature_name, signing_key, hash_algorithm
    )
