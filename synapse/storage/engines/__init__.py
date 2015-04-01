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

from .maria import MariaEngine
from .sqlite3 import Sqlite3Engine


SUPPORTED_MODULE = {
    "sqlite3": Sqlite3Engine,
    "mysql.connector": MariaEngine,
}


def create_engine(name):
    engine_class = SUPPORTED_MODULE.get(name, None)

    if engine_class:
        module = __import__(name)
        return engine_class(module)

    raise RuntimeError(
        "Unsupported database engine '%s'" % (name,)
    )
