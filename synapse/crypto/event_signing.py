# -*- coding: utf-8 -*-

# Copyright 2014 OpenMarket Ltd
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


from synapse.federation.units import Pdu
from synapse.api.events.utils import prune_pdu, prune_event
from syutil.jsonutil import encode_canonical_json
from syutil.base64util import encode_base64, decode_base64
from syutil.crypto.jsonsign import sign_json, verify_signed_json

import copy
import hashlib
import logging

logger = logging.getLogger(__name__)


def add_event_pdu_content_hash(pdu, hash_algorithm=hashlib.sha256):
    hashed = _compute_content_hash(pdu, hash_algorithm)
    pdu.hashes[hashed.name] = encode_base64(hashed.digest())
    return pdu


def check_event_pdu_content_hash(pdu, hash_algorithm=hashlib.sha256):
    """Check whether the hash for this PDU matches the contents"""
    computed_hash = _compute_content_hash(pdu, hash_algorithm)
    if computed_hash.name not in pdu.hashes:
        raise Exception("Algorithm %s not in hashes %s" % (
            computed_hash.name, list(pdu.hashes)
        ))
    message_hash_base64 = pdu.hashes[computed_hash.name]
    try:
        message_hash_bytes = decode_base64(message_hash_base64)
    except:
        raise Exception("Invalid base64: %s" % (message_hash_base64,))
    return message_hash_bytes == computed_hash.digest()


def _compute_content_hash(pdu, hash_algorithm):
    pdu_json = pdu.get_dict()
    #TODO: Make "age_ts" key internal
    pdu_json.pop("age_ts", None)
    pdu_json.pop("unsigned", None)
    pdu_json.pop("signatures", None)
    pdu_json.pop("hashes", None)
    pdu_json_bytes = encode_canonical_json(pdu_json)
    return hash_algorithm(pdu_json_bytes)


def compute_pdu_event_reference_hash(pdu, hash_algorithm=hashlib.sha256):
    tmp_pdu = Pdu(**pdu.get_dict())
    tmp_pdu = prune_pdu(tmp_pdu)
    pdu_json = tmp_pdu.get_dict()
    pdu_json.pop("signatures", None)
    pdu_json_bytes = encode_canonical_json(pdu_json)
    hashed = hash_algorithm(pdu_json_bytes)
    return (hashed.name, hashed.digest())


def compute_event_reference_hash(event, hash_algorithm=hashlib.sha256):
    tmp_event = copy.deepcopy(event)
    tmp_event = prune_event(tmp_event)
    event_json = tmp_event.get_dict()
    event_json.pop("signatures", None)
    event_json_bytes = encode_canonical_json(event_json)
    hashed = hash_algorithm(event_json_bytes)
    return (hashed.name, hashed.digest())


def sign_event_pdu(pdu, signature_name, signing_key):
    tmp_pdu = Pdu(**pdu.get_dict())
    tmp_pdu = prune_pdu(tmp_pdu)
    pdu_json = tmp_pdu.get_dict()
    pdu_json = sign_json(pdu_json, signature_name, signing_key)
    pdu.signatures = pdu_json["signatures"]
    return pdu


def verify_signed_event_pdu(pdu, signature_name, verify_key):
    tmp_pdu = Pdu(**pdu.get_dict())
    tmp_pdu = prune_pdu(tmp_pdu)
    pdu_json = tmp_pdu.get_dict()
    verify_signed_json(pdu_json, signature_name, verify_key)


def add_hashes_and_signatures(event, signature_name, signing_key,
                              hash_algorithm=hashlib.sha256):
    tmp_event = copy.deepcopy(event)
    tmp_event = prune_event(tmp_event)
    redact_json = tmp_event.get_dict()
    redact_json.pop("signatures", None)
    redact_json = sign_json(redact_json, signature_name, signing_key)
    event.signatures = redact_json["signatures"]

    event_json = event.get_full_dict()
    #TODO: We need to sign the JSON that is going out via fedaration.
    event_json.pop("age_ts", None)
    event_json.pop("unsigned", None)
    event_json.pop("signatures", None)
    event_json.pop("hashes", None)
    event_json_bytes = encode_canonical_json(event_json)
    hashed = hash_algorithm(event_json_bytes)
    event.hashes[hashed.name] = encode_base64(hashed.digest())
