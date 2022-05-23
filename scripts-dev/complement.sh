#!/usr/bin/env bash
# This script is designed for developers who want to test their code
# against Complement.
#
# It makes a Synapse image which represents the current checkout,
# builds a synapse-complement image on top, then runs tests with it.
#
# By default the script will fetch the latest Complement main branch and
# run tests with that. This can be overridden to use a custom Complement
# checkout by setting the COMPLEMENT_DIR environment variable to the
# filepath of a local Complement checkout or by setting the COMPLEMENT_REF
# environment variable to pull a different branch or commit.
#
# By default Synapse is run in monolith mode. This can be overridden by
# setting the WORKERS environment variable.
#
# A regular expression of test method names can be supplied as the first
# argument to the script. Complement will then only run those tests. If
# no regex is supplied, all tests are run. For example;
#
# ./complement.sh "TestOutboundFederation(Profile|Send)"
#

# Exit if a line returns a non-zero exit code
set -e

# enable buildkit for the docker builds
export DOCKER_BUILDKIT=1

# Change to the repository root
cd "$(dirname $0)/.."

# Check for a user-specified Complement checkout
if [[ -z "$COMPLEMENT_DIR" ]]; then
  COMPLEMENT_REF=${COMPLEMENT_REF:-main}
  echo "COMPLEMENT_DIR not set. Fetching Complement checkout from ${COMPLEMENT_REF}..."
  wget -Nq https://github.com/matrix-org/complement/archive/${COMPLEMENT_REF}.tar.gz
  tar -xzf ${COMPLEMENT_REF}.tar.gz
  COMPLEMENT_DIR=complement-${COMPLEMENT_REF}
  echo "Checkout available at 'complement-${COMPLEMENT_REF}'"
fi

# Build the base Synapse image from the local checkout
docker build -t matrixdotorg/synapse -f "docker/Dockerfile" .

extra_test_args=()

test_tags="synapse_blacklist,msc2716,msc3030"

# If we're using workers, modify the docker files slightly.
if [[ -n "$WORKERS" ]]; then
  # Build the workers docker image (from the base Synapse image).
  docker build -t matrixdotorg/synapse-workers -f "docker/Dockerfile-workers" .

  export COMPLEMENT_BASE_IMAGE=complement-synapse-workers
  COMPLEMENT_DOCKERFILE=SynapseWorkers.Dockerfile

  # And provide some more configuration to complement.

  # It can take quite a while to spin up a worker-mode Synapse for the first
  # time (the main problem is that we start 14 python processes for each test,
  # and complement likes to do two of them in parallel).
  export COMPLEMENT_SPAWN_HS_TIMEOUT_SECS=120

  # ... and it takes longer than 10m to run the whole suite.
  extra_test_args+=("-timeout=60m")
else
  export COMPLEMENT_BASE_IMAGE=complement-synapse
  COMPLEMENT_DOCKERFILE=Dockerfile

  # We only test faster room joins on monoliths, because they are purposefully
  # being developed without worker support to start with.
  test_tags="$test_tags,faster_joins"
fi

# Build the Complement image from the Synapse image we just built.
docker build -t $COMPLEMENT_BASE_IMAGE -f "docker/complement/$COMPLEMENT_DOCKERFILE" "docker/complement"

# Run the tests!
echo "Images built; running complement"
cd "$COMPLEMENT_DIR"

go test -v -tags $test_tags -count=1 "${extra_test_args[@]}" "$@" ./tests/...
