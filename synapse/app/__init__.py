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

import sys
sys.dont_write_bytecode = True

from synapse import python_dependencies   # noqa: E402

try:
    python_dependencies.check_requirements()
except python_dependencies.MissingRequirementError as e:
    message = "\n".join([
        "Missing Requirement: %s" % (e.message,),
        "To install run:",
        "    pip install --upgrade --force \"%s\"" % (e.dependency,),
        "",
    ])
    sys.stderr.writelines(message)
    sys.exit(1)
