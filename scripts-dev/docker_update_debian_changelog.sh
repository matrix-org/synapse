#!/bin/bash -e
# Copyright 2021 The Matrix.org Foundation C.I.C.
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

# This script is meant to be used inside a Docker container to run the `dch` incantations
# needed to release Synapse. This is useful on systems like macOS where such scripts are
# not easily accessible.
#
# Running it (when if the current working directory is the root of the Synapse checkout):
#   docker run --rm -v $PWD:/synapse ubuntu:latest /synapse/scripts-dev/docker_update_debian_changelog.sh VERSION
#
# The image can be replaced by any other Debian-based image (as long as the `devscripts`
# package exists in the default repository).
# `VERSION` is the version of Synapse being released without the leading "v" (e.g. 1.42.0).

# Check if a version was provided.
if [ "$#" -ne 1 ]; then
  echo "Usage: update_debian_changelog.sh VERSION"
  echo "VERSION is the version of Synapse being released in the form 1.42.0 (without the leading \"v\")"
  exit 1
fi

# Check that apt-get is available on the system.
if ! which apt-get > /dev/null 2>&1; then
  echo "\"apt-get\" isn't available on this system. This script needs to be run in a Docker container using a Debian-based image."
  exit 1
fi

# Check if devscripts is available in the default repos for this distro.
# Update the apt package list cache.
# We need to do this before we can search the apt cache or install devscripts.
apt-get update || exit 1

if ! apt-cache search devscripts | grep -E "^devscripts \-" > /dev/null; then
  echo "The package \"devscripts\" needs to exist in the default repositories for this distribution."
  exit 1
fi

# We set -x here rather than in the shebang so that if we need to exit early because no
# version was provided, the message doesn't get drowned in useless output.
set -x

# Make the root of the Synapse checkout the current working directory.
cd /synapse

# Install devscripts (which provides dch). We need to make the Debian frontend
# noninteractive because installing devscripts otherwise asks for the machine's location.
DEBIAN_FRONTEND=noninteractive apt-get install -y devscripts

# Update the Debian changelog.
ver=${1}
dch -M -v "$(sed -Ee 's/(rc|a|b|c)/~\1/' <<<"$ver")" "New synapse release $ver."
dch -M -r -D stable ""
