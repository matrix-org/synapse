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

# First calculate the various trial jobs.
#
# For each type of test we only run on Py3.7 on PRs

trial_sqlite_tests = [
    {
        "python-version": "3.7",
        "database": "sqlite",
        "extras": "all",
    }
]

if not IS_PR:
    trial_sqlite_tests.extend(
        {
            "python-version": version,
            "database": "sqlite",
            "extras": "all",
        }
        for version in ("3.8", "3.9", "3.10")
    )


trial_postgres_tests = [
    {
        "python-version": "3.7",
        "database": "postgres",
        "postgres-version": "10",
        "extras": "all",
    }
]

if not IS_PR:
    trial_postgres_tests.append(
        {
            "python-version": "3.10",
            "database": "postgres",
            "postgres-version": "14",
            "extras": "all",
        }
    )

trial_no_extra_tests = [
    {
        "python-version": "3.7",
        "database": "sqlite",
        "extras": "",
    }
]

print("::group::Calculated trial jobs")
print(
    json.dumps(
        trial_sqlite_tests + trial_postgres_tests + trial_no_extra_tests, indent=4
    )
)
print("::endgroup::")

test_matrix = json.dumps(
    trial_sqlite_tests + trial_postgres_tests + trial_no_extra_tests
)
print(f"::set-output name=trial_test_matrix::{test_matrix}")


# First calculate the various sytest jobs.
#
# For each type of test we only run on focal on PRs


sytest_tests = [
    {
        "sytest-tag": "focal",
    },
    {
        "sytest-tag": "focal",
        "postgres": "postgres",
    },
    {
        "sytest-tag": "focal",
        "postgres": "multi-postgres",
        "workers": "workers",
    },
]

if not IS_PR:
    sytest_tests.extend(
        [
            {
                "sytest-tag": "testing",
                "postgres": "postgres",
            },
            {
                "sytest-tag": "buster",
                "postgres": "multi-postgres",
                "workers": "workers",
            },
        ]
    )


print("::group::Calculated sytest jobs")
print(json.dumps(sytest_tests, indent=4))
print("::endgroup::")

test_matrix = json.dumps(sytest_tests)
print(f"::set-output name=sytest_test_matrix::{test_matrix}")


# Calculate a comprehensive list of workers by type to hunt for specific problems with them.
# Won't need to include if it's a 'worker' setup, because obviously it is. Postgres is implied
# because it's necessary for worker at this time.

complement_single_worker_tests = [
    {
        "worker_types": workers,
    }
    for workers in (
        "account_data",
        "appservice",
        "background_worker",
        "event_creator",
        "event_persister",
        "federation_inbound",
        "federation_reader",
        "federation_sender",
        "frontend_proxy",
        "media_repository",
        "presence",
        "pusher",
        "receipts",
        "synchrotron",
        "to_device",
        "typing",
        "user_dir",
    )
]

complement_sharding_worker_tests = [
    {"worker_types": "event_persister, event_persister, event_persister"},
    {"worker_types": "federation_sender, federation_sender, federation_sender"},
    {"worker_types": "pusher, pusher, pusher"},
    {"worker_types": "synchrotron, synchrotron, synchrotron"},
]

complement_stream_writers_worker_tests = [
    {
        "worker_types": "account_data, event_persister, presence, receipts, to_device, typing"
    }
]

complement_fullset_worker_tests = [
    {
        "worker_types": "account_data, appservice, background_worker, event_creator, event_persister, event_persister, federation_inbound, federation_reader, federation_sender, federation_sender, frontend_proxy, media_repository, pusher, pusher, synchrotron, to_device, typing, user_dir"
    }
]

print("::group::Calculated Complement jobs")
print(
    json.dumps(
        complement_single_worker_tests
        + complement_sharding_worker_tests
        + complement_stream_writers_worker_tests
        + complement_fullset_worker_tests,
        indent=4,
    )
)
print("::endgroup::")

test_matrix = json.dumps(complement_single_worker_tests)
print(f"::set-output name=complement_singles_test_matrix::{test_matrix}")
test_matrix = json.dumps(complement_sharding_worker_tests)
print(f"::set-output name=complement_sharding_test_matrix::{test_matrix}")
test_matrix = json.dumps(complement_stream_writers_worker_tests)
print(f"::set-output name=complement_stream_writers_test_matrix::{test_matrix}")
test_matrix = json.dumps(complement_fullset_worker_tests)
print(f"::set-output name=complement_fullset_test_matrix::{test_matrix}")
