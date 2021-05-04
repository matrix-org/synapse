#!/usr/bin/env bash
# This script is designed for developers who want to test their code
# against Complement.
#
# It makes a Synapse image which represents the current checkout,
# builds a synapse-complement image on top, then runs tests with it.
#
# By default the script will fetch the latest Complement master branch and
# run tests with that. This can be overridden to use a custom Complement
# checkout by setting the COMPLEMENT_DIR environment variable to the
# filepath of a local Complement checkout.
#
# A regular expression of test method names can be supplied as the first
# argument to the script. Complement will then only run those tests. If
# no regex is supplied, all tests are run. For example;
#
# ./complement.sh "TestOutboundFederation(Profile|Send)"
#

# Exit if a line returns a non-zero exit code
set -e

# Change to the repository root
cd "$(dirname $0)/.."

# Check for a user-specified Complement checkout
if [[ -z "$COMPLEMENT_DIR" ]]; then
  echo "COMPLEMENT_DIR not set. Fetching the latest Complement checkout..."
  wget -Nq https://github.com/matrix-org/complement/archive/master.tar.gz
  tar -xzf master.tar.gz
  COMPLEMENT_DIR=complement-master
  echo "Checkout available at 'complement-master'"
fi

# Build the base Synapse image from the local checkout
docker build -t matrixdotorg/synapse -f docker/Dockerfile .
# Build the Synapse monolith image from Complement, based on the above image we just built
docker build -t complement-synapse -f "$COMPLEMENT_DIR/dockerfiles/Synapse.Dockerfile" "$COMPLEMENT_DIR/dockerfiles"

cd "$COMPLEMENT_DIR"

EXTRA_COMPLEMENT_ARGS=""
if [[ -n "$1" ]]; then
  # A test name regex has been set, supply it to Complement
  EXTRA_COMPLEMENT_ARGS+="-run $1 "
fi

# Run the tests!
COMPLEMENT_BASE_IMAGE=complement-synapse go test -v -tags synapse_blacklist,msc2946,msc3083 -count=1 $EXTRA_COMPLEMENT_ARGS ./tests
