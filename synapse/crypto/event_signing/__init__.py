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
    """Check whether the hash for this PDU matches the contents"""
    return v1.check_event_content_hash(event, hash_algorithm)


def compute_event_reference_hash(
    event, hash_algorithm=hashlib.sha256, room_version=RoomVersions.V1
):
    return v1.compute_event_reference_hash(event, hash_algorithm)


def compute_event_signature(event, signature_name, signing_key,
                            room_version=RoomVersions.V1):
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
    return v1.add_hashes_and_signatures(
        event, signature_name, signing_key, hash_algorithm
    )
