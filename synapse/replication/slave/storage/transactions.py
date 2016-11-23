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
from synapse.storage.transactions import TransactionStore


class TransactionStore(BaseSlavedStore):
    get_destination_retry_timings = TransactionStore.__dict__[
        "get_destination_retry_timings"
    ]
    _get_destination_retry_timings = DataStore._get_destination_retry_timings.__func__
    set_destination_retry_timings = DataStore.set_destination_retry_timings.__func__
    _set_destination_retry_timings = DataStore._set_destination_retry_timings.__func__

    prep_send_transaction = DataStore.prep_send_transaction.__func__
    delivered_txn = DataStore.delivered_txn.__func__
