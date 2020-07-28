#!/bin/bash
#
# Copyright 2020 The Matrix.org Foundation C.I.C.
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
#
# This script checks that line terminators in all repository files (excluding
# those in the .git directory) feature unix line terminators.
#
# Usage:
#
# ./check_line_terminators.sh
#
# The script will emit exit code 1 if any files that do not use unix line
# terminators are found, 0 otherwise.

# cd to the root of the repository
cd `dirname $0`/..

# Find and print files with non-unix line terminators
if find . -path './.git/*' -prune -o -type f -print0 | xargs -0 grep -I -l $'\r$'; then
    echo -e '\e[31mERROR: found files with CRLF line endings. See above.\e[39m'
    exit 1
fi
