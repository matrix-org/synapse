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

import os
import sys
from hashlib import blake2b

import synapse
from synapse.synapse_rust import get_rust_file_digest


def check_rust_lib_up_to_date() -> None:
    """For editable installs check if the rust library is outdated and needs to
    be rebuilt.
    """

    if not _dist_is_editable():
        return

    synapse_dir = os.path.dirname(synapse.__file__)
    synapse_root = os.path.abspath(os.path.join(synapse_dir, ".."))

    # Double check we've not gone into site-packages...
    if os.path.basename(synapse_root) == "site-packages":
        return

    # ... and it looks like the root of a python project.
    if not os.path.exists("pyproject.toml"):
        return

    # Get the hash of all Rust source files
    hash = _hash_rust_files_in_directory(os.path.join(synapse_root, "rust", "src"))

    if hash != get_rust_file_digest():
        raise Exception("Rust module outdated. Please rebuild using `poetry install`")


def _hash_rust_files_in_directory(directory: str) -> str:
    """Get the hash of all files in a directory (recursively)"""

    directory = os.path.abspath(directory)

    paths = []

    dirs = [directory]
    while dirs:
        dir = dirs.pop()
        with os.scandir(dir) as d:
            for entry in d:
                if entry.is_dir():
                    dirs.append(entry.path)
                else:
                    paths.append(entry.path)

    # We sort to make sure that we get a consistent and well-defined ordering.
    paths.sort()

    hasher = blake2b()

    for path in paths:
        with open(os.path.join(directory, path), "rb") as f:
            hasher.update(f.read())

    return hasher.hexdigest()


def _dist_is_editable() -> bool:
    """Is distribution an editable install?"""
    for path_item in sys.path:
        egg_link = os.path.join(path_item, "matrix-synapse.egg-link")
        if os.path.isfile(egg_link):
            return True
    return False
