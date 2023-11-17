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
import json
import sys
from collections import defaultdict
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


def calculate_version_chart() -> str:
    repo = git.Repo(path=".")

    schema_version = None
    schema_compat_version = None

    # Map of schema version -> Synapse versions at that schema.
    schema_versions = defaultdict(list)

    # Find ranges of versions which are compatible with a schema version.
    #
    # There are two modes of operation:
    #
    # 1. If schema_compat_version is None, then Synapse can only move to a new
    #    version with schema_version >= its current version.
    # 2. If schema_compat_version is *not* None, then Synapse can move to a new
    #    version with schema version >= schema_compat_version.
    #
    # See https://github.com/matrix-org/synapse/pull/9933 which was included in v1.37.0.
    for tag in get_tags(repo):
        schema_version, schema_compat_version = get_schema_versions(tag)

        # If a schema compat version is given, prefer that over the schema version.
        schema_versions[schema_compat_version or schema_version].append(tag.name)

    # Generate a table of which maps a version to the version it can be rolled back to.
    result = "| Synapse version | Backwards compatible version |\n"
    result += "|-----------------|------------------------------|\n"
    for synapse_versions in schema_versions.values():
        result += f"| {synapse_versions[-1]: ^15} | {synapse_versions[0]: ^28} |\n"

    return result


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "supports":
        # We don't care about the renderer which is being used, which is the second argument.
        sys.exit(0)
    else:
        # Expect JSON data on stdin.
        context, book = json.load(sys.stdin)

        for section in book["sections"]:
            if "Chapter" in section and section["Chapter"]["path"] == "upgrade.md":
                section["Chapter"]["content"] = section["Chapter"]["content"].replace(
                    "<!-- REPLACE_WITH_SCHEMA_VERSIONS -->", calculate_version_chart()
                )

        # Print the result back out to stdout.
        print(json.dumps(book))
