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


class ThirdPartyInvites(object):
    INVITE_KEYS = {"id_server", "medium", "address", "display_name"}

    JOIN_KEYS = {
        "token",
        "public_key",
        "key_validity_url",
        "signature",
        "sender",
    }

    @classmethod
    def has_invite_keys(cls, content):
        for key in cls.INVITE_KEYS:
            if key not in content:
                return False
        return True

    @classmethod
    def has_join_keys(cls, content):
        for key in cls.JOIN_KEYS:
            if key not in content:
                return False
        return True

    @classmethod
    def copy_join_keys(cls, src, dst):
        for key in cls.JOIN_KEYS:
            if key in src:
                dst[key] = src[key]

    @classmethod
    @defer.inlineCallbacks
    def check_key_valid(cls, http_client, event):
        try:
            response = yield http_client.get_json(
                event.content["key_validity_url"],
                {"public_key": event.content["public_key"]}
            )
            if not response["valid"]:
                raise AuthError(403, "Third party certificate was invalid")
        except IOError:
            raise AuthError(403, "Third party certificate could not be checked")
