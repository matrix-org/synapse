# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
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


from ._base import BaseSlavedStore

from synapse.storage import DataStore


class SlavedPushActionsStore(BaseSlavedStore):

    get_unread_push_actions_for_user_in_range = (
        DataStore.get_unread_push_actions_for_user_in_range.__func__
    )

    get_push_action_users_in_range = (
        DataStore.get_push_action_users_in_range.__func__
    )
