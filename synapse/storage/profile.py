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

from twisted.internet import defer

from ._base import SQLBaseStore

import ujson


class ProfileStore(SQLBaseStore):
    def create_profile(self, user_localpart):
        return self._simple_insert(
            table="profiles",
            values={"user_id": user_localpart},
            desc="create_profile",
        )

    def get_profile_displayname(self, user_localpart):
        return self._simple_select_one_onecol(
            table="profiles",
            keyvalues={"user_id": user_localpart},
            retcol="displayname",
            desc="get_profile_displayname",
        )

    def set_profile_displayname(self, user_localpart, new_displayname):
        return self._simple_update_one(
            table="profiles",
            keyvalues={"user_id": user_localpart},
            updatevalues={"displayname": new_displayname},
            desc="set_profile_displayname",
        )

    def get_profile_avatar_url(self, user_localpart):
        return self._simple_select_one_onecol(
            table="profiles",
            keyvalues={"user_id": user_localpart},
            retcol="avatar_url",
            desc="get_profile_avatar_url",
        )

    def set_profile_avatar_url(self, user_localpart, new_avatar_url):
        return self._simple_update_one(
            table="profiles",
            keyvalues={"user_id": user_localpart},
            updatevalues={"avatar_url": new_avatar_url},
            desc="set_profile_avatar_url",
        )

    @defer.inlineCallbacks
    def get_full_profile(self, user_id):
        rows = yield self._simple_select_list(
            table="profiles_extended",
            keyvalues={"user_id": user_id},
            retcols=("persona", "key", "content",),
        )

        personas = {}
        profile = {"personas": personas}
        for row in rows:
            content = ujson.loads(row["content"])
            personas.setdefault(
                row["persona"], {"rows": {}}
            )["entries"][row["key"]] = content

        defer.returnValue(profile)

    @defer.inlineCallbacks
    def get_persona_profile(self, user_id, persona):
        rows = yield self._simple_select_list(
            table="profiles_extended",
            keyvalues={
                "user_id": user_id,
                "persona": persona,
            },
            retcols=("key", "content",),
        )

        persona = {"rows": {
            row["key"]: ujson.loads(row["content"])
            for row in rows
        }}

        defer.returnValue(persona)

    @defer.inlineCallbacks
    def get_profile_key(self, user_id, persona, key):
        content_json = yield self._simple_select_one_onecol(
            table="profiles_extended",
            keyvalues={
                "user_id": user_id,
                "persona": persona,
                "key": key,
            },
            retcol="content",
            allow_none=True,
        )

        if content_json:
            content = ujson.loads(content_json)
        else:
            content = None

        defer.returnValue(content)

    def update_profile_key(self, user_id, persona, key, content):
        content_json = ujson.dumps(content)

        def _update_profile_key_txn(txn, stream_id):
            self._simple_delete_txn(
                txn,
                table="profiles_extended",
                keyvalues={
                    "user_id": user_id,
                    "persona": persona,
                    "key": key,
                }
            )

            self._simple_insert_txn(
                txn,
                table="profiles_extended",
                values={
                    "stream_id": stream_id,
                    "user_id": user_id,
                    "persona": persona,
                    "key": key,
                    "content": content_json,
                }
            )

        with self._profiles_id_gen.get_next() as stream_id:
            return self.runInteraction(
                "update_profile_key", _update_profile_key_txn,
                stream_id,
            )
