# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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


class AccountDataEventSource:
    def __init__(self, hs):
        self.store = hs.get_datastore()

    def get_current_key(self, direction="f"):
        return self.store.get_max_account_data_stream_id()

    async def get_new_events(self, user, from_key, **kwargs):
        user_id = user.to_string()
        last_stream_id = from_key

        current_stream_id = self.store.get_max_account_data_stream_id()

        results = []
        tags = await self.store.get_updated_tags(user_id, last_stream_id)

        for room_id, room_tags in tags.items():
            results.append(
                {"type": "m.tag", "content": {"tags": room_tags}, "room_id": room_id}
            )

        (
            account_data,
            room_account_data,
        ) = await self.store.get_updated_account_data_for_user(user_id, last_stream_id)

        for account_data_type, content in account_data.items():
            results.append({"type": account_data_type, "content": content})

        for room_id, account_data in room_account_data.items():
            for account_data_type, content in account_data.items():
                results.append(
                    {"type": account_data_type, "content": content, "room_id": room_id}
                )

        return results, current_stream_id
