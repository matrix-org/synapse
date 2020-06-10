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

import logging

from synapse.storage._base import SQLBaseStore

logger = logging.getLogger(__name__)


class RejectionsStore(SQLBaseStore):
    def get_rejection_reason(self, event_id):
        return self.db.simple_select_one_onecol(
            table="rejections",
            retcol="reason",
            keyvalues={"event_id": event_id},
            allow_none=True,
            desc="get_rejection_reason",
        )
