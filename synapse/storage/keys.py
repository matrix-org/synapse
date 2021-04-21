# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2019 New Vector Ltd.
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

import attr
from signedjson.types import VerifyKey

logger = logging.getLogger(__name__)


@attr.s(slots=True, frozen=True)
class FetchKeyResult:
    verify_key = attr.ib(type=VerifyKey)  # the key itself
    valid_until_ts = attr.ib(type=int)  # how long we can use this key for
