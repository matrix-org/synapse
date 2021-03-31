#! /bin/bash -eu
# This script is designed for developers who want to test their code
# against Complement.
#
# It makes a Synapse image which represents the current checkout,
# then downloads Complement and runs it with that image.

cd "$(dirname $0)/.."

# Build the base Synapse image from the local checkout
docker build -t matrixdotorg/synapse:latest -f docker/Dockerfile .

# Download Complement
cd ../complement

# Build the Synapse image from Complement, based on the above image we just built
docker build -t complement-synapse -f dockerfiles/Synapse.Dockerfile ./dockerfiles

# Run the tests on the resulting image!
COMPLEMENT_BASE_IMAGE=complement-synapse go test -tags msc2716 -v -count=1 ./tests/main_test.go ./tests/msc2716_test.go -run TestBackfillingHistory/parallel/Backfilled_historical_events_resolve_with_proper_state
