# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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

from twisted.trial import unittest

import logging


# logging doesn't have a "don't log anything at all EVARRRR setting,
# but since the highest value is 50, 1000000 should do ;)
NEVER = 1000000

logging.getLogger().addHandler(logging.StreamHandler())
logging.getLogger().setLevel(NEVER)


class TestCase(unittest.TestCase):
    pass
