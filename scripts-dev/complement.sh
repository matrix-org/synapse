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
# ./complement.sh -run "TestOutboundFederation(Profile|Send)"
#

# Exit if a line returns a non-zero exit code
set -e


# Helper to emit annotations that collapse portions of the log in GitHub Actions
echo_if_github() {
  if [[ -n "$GITHUB_WORKFLOW" ]]; then
    echo $*
  fi
}


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
echo_if_github "::group::Build Docker image: matrixdotorg/synapse"
docker build -t matrixdotorg/synapse -f "docker/Dockerfile" .
echo_if_github "::endgroup::"

# Build the workers docker image (from the base Synapse image we just built).
echo_if_github "::group::Build Docker image: matrixdotorg/synapse-workers"
docker build -t matrixdotorg/synapse-workers -f "docker/Dockerfile-workers" .
echo_if_github "::endgroup::"

# Build the unified Complement image (from the worker Synapse image we just built).
echo_if_github "::group::Build Docker image: complement/Dockerfile"
docker build -t complement-synapse \
  -f "docker/complement/Dockerfile" "docker/complement"
echo_if_github "::endgroup::"

export COMPLEMENT_BASE_IMAGE=complement-synapse

extra_test_args=()

test_tags="synapse_blacklist,msc2716,msc3030,msc3787"

# All environment variables starting with PASS_ will be shared.
# (The prefix is stripped off before reaching the container.)
export COMPLEMENT_SHARE_ENV_PREFIX=PASS_

# It takes longer than 10m to run the whole suite.
extra_test_args+=("-timeout=60m")

if [[ -n "$WORKERS" ]]; then
  # Use workers.
  export PASS_SYNAPSE_COMPLEMENT_USE_WORKERS=true

  # Workers can only use Postgres as a database.
  export PASS_SYNAPSE_COMPLEMENT_DATABASE=postgres

  # And provide some more configuration to complement.

  # It can take quite a while to spin up a worker-mode Synapse for the first
  # time (the main problem is that we start 14 python processes for each test,
  # and complement likes to do two of them in parallel).
  export COMPLEMENT_SPAWN_HS_TIMEOUT_SECS=120
else
  export PASS_SYNAPSE_COMPLEMENT_USE_WORKERS=
  if [[ -n "$POSTGRES" ]]; then
    export PASS_SYNAPSE_COMPLEMENT_DATABASE=postgres
  else
    export PASS_SYNAPSE_COMPLEMENT_DATABASE=sqlite
  fi

  # We only test faster room joins on monoliths, because they are purposefully
  # being developed without worker support to start with.
  test_tags="$test_tags,faster_joins"
fi

# Run the tests!
echo "Images built; running complement"
cd "$COMPLEMENT_DIR"

go test -v -tags $test_tags -count=1 "${extra_test_args[@]}" "$@" ./tests/...
