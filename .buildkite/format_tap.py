# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.
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
from tap.parser import Parser
from tap.line import Result, Unknown, Diagnostic

out = ["### TAP Output for " + sys.argv[2]]

p = Parser()

in_error = False

for line in p.parse_file(sys.argv[1]):
    if isinstance(line, Result):
        if in_error:
            out.append("")
            out.append("</pre></code></details>")
            out.append("")
            out.append("----")
            out.append("")
        in_error = False

        if not line.ok and not line.todo:
            in_error = True

            out.append("FAILURE Test #%d: ``%s``" % (line.number, line.description))
            out.append("")
            out.append("<details><summary>Show log</summary><code><pre>")

    elif isinstance(line, Diagnostic) and in_error:
        out.append(line.text)

if out:
    for line in out[:-3]:
        print(line)
