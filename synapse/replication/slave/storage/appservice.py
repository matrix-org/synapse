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
from synapse.config.appservice import load_appservices


class SlavedApplicationServiceStore(BaseSlavedStore):
    def __init__(self, db_conn, hs):
        super(SlavedApplicationServiceStore, self).__init__(db_conn, hs)
        self.services_cache = load_appservices(
            hs.config.server_name,
            hs.config.app_service_config_files
        )

    get_app_service_by_token = DataStore.get_app_service_by_token.__func__
    get_app_service_by_user_id = DataStore.get_app_service_by_user_id.__func__
    get_app_services = DataStore.get_app_services.__func__
    get_new_events_for_appservice = DataStore.get_new_events_for_appservice.__func__
    create_appservice_txn = DataStore.create_appservice_txn.__func__
    get_appservices_by_state = DataStore.get_appservices_by_state.__func__
    get_oldest_unsent_txn = DataStore.get_oldest_unsent_txn.__func__
    _get_last_txn = DataStore._get_last_txn.__func__
    complete_appservice_txn = DataStore.complete_appservice_txn.__func__
    get_appservice_state = DataStore.get_appservice_state.__func__
    set_appservice_last_pos = DataStore.set_appservice_last_pos.__func__
    set_appservice_state = DataStore.set_appservice_state.__func__
