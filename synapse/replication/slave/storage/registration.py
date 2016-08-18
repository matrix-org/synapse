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

from ._base import BaseSlavedStore
from synapse.storage import DataStore
from synapse.storage.registration import RegistrationStore


class SlavedRegistrationStore(BaseSlavedStore):
    def __init__(self, db_conn, hs):
        super(SlavedRegistrationStore, self).__init__(db_conn, hs)

    # TODO: use the cached version and invalidate deleted tokens
    get_user_by_access_token = RegistrationStore.__dict__[
        "get_user_by_access_token"
    ]

    _query_for_auth = DataStore._query_for_auth.__func__
    get_user_by_id = RegistrationStore.__dict__[
        "get_user_by_id"
    ]
