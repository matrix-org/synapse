#!/usr/bin/env python
# Copyright 2023 The Matrix.org Foundation C.I.C.
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

import io
from typing import Iterator, Optional, Tuple

import git
from packaging import version

# The schema version has moved around over the years.
SCHEMA_VERSION_FILES = (
    "synapse/storage/schema/__init__.py",
    "synapse/storage/prepare_database.py",
    "synapse/storage/__init__.py",
    "synapse/app/homeserver.py",
)


def get_schema_versions(tag: git.Tag) -> Tuple[Optional[int], Optional[int]]:
    """Get the schema and schema compat versions for a tag."""
    schema_version = None
    schema_compat_version = None

    for file in SCHEMA_VERSION_FILES:
        try:
            schema_file = tag.commit.tree / file
        except KeyError:
            continue

        # We (usually) can't execute the code since it might have unknown imports.
        if file != "synapse/storage/schema/__init__.py":
            with io.BytesIO(schema_file.data_stream.read()) as f:
                for line in f.readlines():
                    if line.startswith(b"SCHEMA_VERSION"):
                        schema_version = int(line.split()[2])

                    # Bail early.
                    if schema_version:
                        break
        else:
            # SCHEMA_COMPAT_VERSION is sometimes across multiple lines, the easist
            # thing to do is exec the code. Luckily it has only ever existed in
            # a file which imports nothing else from Synapse.
            locals = {}
            exec(schema_file.data_stream.read().decode("utf-8"), {}, locals)
            schema_version = locals["SCHEMA_VERSION"]
            schema_compat_version = locals.get("SCHEMA_COMPAT_VERSION")

    return schema_version, schema_compat_version


def get_tags(repo: git.Repo) -> Iterator[git.Tag]:
    """Return an iterator of tags sorted by version."""
    tags = []
    for tag in repo.tags:
        # All "real" Synapse tags are of the form vX.Y.Z.
        if not tag.name.startswith("v"):
            continue

        # There's a weird tag from the initial react UI.
        if tag.name == "v0.1":
            continue

        try:
            tag_version = version.parse(tag.name)
        except version.InvalidVersion:
            # Skip invalid versions.
            continue

        # Skip pre- and post-release versions.
        if tag_version.is_prerelease or tag_version.is_postrelease or tag_version.local:
            continue

        tags.append((tag_version, tag))

    # Sort based on the version number (not lexically).
    return (tag for _, tag in sorted(tags, key=lambda t: t[0]))


if __name__ == "__main__":
    repo = git.Repo(path=".")

    schema_version = None
    schema_compat_version = None

    # Maps of schema versions -> Synapse version.
    schema_versions = {}
    schema_compat_versions = {}

    for tag in get_tags(repo):
        cur_schema_version, cur_schema_compat_version = get_schema_versions(tag)

        if schema_version != cur_schema_version:
            schema_versions[cur_schema_version] = tag.name
            schema_version = cur_schema_version
        if schema_compat_version != cur_schema_compat_version:
            schema_compat_versions[cur_schema_compat_version] = tag.name
            schema_compat_version = cur_schema_compat_version

    # Generate a table of which maps a version to the version it can be rolled back to.
    print("| Synapse version | Backwards compatible version |")
    print("|-----------------|------------------------------|")
    # v1.37.0 was when the schema compat version was added.
    #
    # See https://github.com/matrix-org/synapse/pull/9933.
    for schema_compat_version, synapse_version in schema_compat_versions.items():
        print(
            f"| {synapse_version: ^15} | {schema_versions[schema_compat_version]: ^28} |"
        )
