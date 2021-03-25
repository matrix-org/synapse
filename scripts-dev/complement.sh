#!/usr/bin/env bash
# This script is designed for developers who want to test their code
# against Complement.
#
# It makes a Synapse image which represents the current checkout,
# builds a synapse-complement image on top, then runs tests with it.
#
# By default the script assumes that a Complement checkout exists next to
# the current Synapse checkout directory. This can be overridden by setting
# the COMPLEMENT_DIR env var to the path to your Complement checkout.
#
# A regular expression of test method names can be supplied as the first
# argument to the script. Complement will then only run those tests. If
# no regex is supplied, all tests are run. Ex.
#
# ./complement.sh "TestOutboundFederation(Profile|Send)"
#

# Exit if a line returns a non-zero exit code
set -e

COMPLEMENT_DIR="${COMPLEMENT_DIR:-$(dirname $0)/../../complement}"

cd "$(dirname $0)/.."

# Build the base Synapse image from the local checkout
docker build -t matrixdotorg/synapse -f docker/Dockerfile .
# Build the Synapse monolith image from Complement, based on the above image we just built
docker build -t complement-synapse -f "$COMPLEMENT_DIR/dockerfiles/Synapse.Dockerfile" "$COMPLEMENT_DIR/dockerfiles"

cd "$COMPLEMENT_DIR"

EXTRA_COMPLEMENT_ARGS=""
if [[ -n $1 ]]; then
  # A test name regex has been set, supply it to Complement
  EXTRA_COMPLEMENT_ARGS+="-run $1 "
fi

# Run the tests!
COMPLEMENT_BASE_IMAGE=complement-synapse go test -v -tags synapse_blacklist $EXTRA_COMPLEMENT_ARGS ./tests
