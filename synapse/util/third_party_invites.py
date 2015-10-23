# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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
from synapse.api.errors import AuthError


INVITE_KEYS = {"id_server", "medium", "address", "display_name"}

JOIN_KEYS = {
    "token",
    "public_key",
    "key_validity_url",
    "sender",
    "signed",
}


def has_invite_keys(content):
    for key in INVITE_KEYS:
        if key not in content:
            return False
    return True


def has_join_keys(content):
    for key in JOIN_KEYS:
        if key not in content:
            return False
    return True


def join_has_third_party_invite(content):
    if "third_party_invite" not in content:
        return False
    return has_join_keys(content["third_party_invite"])


def extract_join_keys(src):
    return {
        key: value
        for key, value in src.items()
        if key in JOIN_KEYS
    }


@defer.inlineCallbacks
def check_key_valid(http_client, event):
    try:
        response = yield http_client.get_json(
            event.content["third_party_invite"]["key_validity_url"],
            {"public_key": event.content["third_party_invite"]["public_key"]}
        )
    except Exception:
        raise AuthError(502, "Third party certificate could not be checked")
    if "valid" not in response or not response["valid"]:
        raise AuthError(403, "Third party certificate was invalid")
