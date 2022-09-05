#!/usr/bin/env python
# Copyright 2022 The Matrix.org Foundation C.I.C.
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

# Calculate the trial jobs to run based on if we're in a PR or not.

import json
import os

IS_PR = os.environ["GITHUB_REF"].startswith("refs/pull/")

sqlite_tests = [
    {
        "python-version": "3.7",
        "database": "sqlite",
        "extras": "all",
    }
]

if not IS_PR:
    sqlite_tests.extend(
        {
            "python-version": version,
            "database": "sqlite",
            "extras": "all",
        }
        for version in ("3.8", "3.9", "3.10")
    )


postgres_tests = [
    {
        "python-version": "3.7",
        "database": "postgres",
        "postgres-version": "10",
        "extras": "all",
    }
]

if not IS_PR:
    postgres_tests.append(
        {
            "python-version": "3.10",
            "database": "postgres",
            "postgres-version": "14",
            "extras": "all",
        }
    )

no_extra_tests = [
    {
        "python-version": "3.7",
        "database": "sqlite",
        "extras": "",
    }
]

print("::group::Calculated jobs")
print(json.dumps(sqlite_tests + postgres_tests + no_extra_tests, indent=4))
print("::endgroup::")

test_matrix = json.dumps(sqlite_tests + postgres_tests + no_extra_tests)
print(f"::set-output name=test_matrix::{test_matrix}")
