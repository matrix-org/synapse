#! /bin/bash -eu
# This script is designed for developers who want to test their code
# against Complement.
#
# It creates a Complement-ready worker-enabled Synapse docker image from
# the local checkout and runs Complement tests against it.
#
# This script assumes that it is located in the scripts-dev folder of a
# Synapse checkout, and that Complement exists at ../../complement
# In my case, I have /home/user/code/complement and /home/user/code/synapse.
COMPLEMENT_DIR="/home/user/code/complement"

cd "$(dirname $0)/.."

# Build the Synapse image from the local checkout
docker build -t matrixdotorg/synapse:latest -f docker/Dockerfile .

# Build the base Synapse worker image
docker build -t matrixdotorg/synapse:workers -f docker/Dockerfile-workers .

cd "$COMPLEMENT_DIR"

# Build the Complement Synapse worker image
docker build -t matrixdotorg/complement-synapse:workers -f dockerfiles/SynapseWorkers.Dockerfile dockerfiles

# Run the tests on the resulting image!
COMPLEMENT_VERSION_CHECK_ITERATIONS=300 COMPLEMENT_DEBUG=1 COMPLEMENT_BASE_IMAGE=matrixdotorg/complement-synapse:workers go test -v -count=1 -tags="synapse_blacklist" -failfast ./tests
#COMPLEMENT_VERSION_CHECK_ITERATIONS=100 COMPLEMENT_DEBUG=1 COMPLEMENT_BASE_IMAGE=complement-synapse go test -v -count=1 -parallel=1 ./tests/

#COMPLEMENT_VERSION_CHECK_ITERATIONS=100 COMPLEMENT_BASE_IMAGE=complement-synapse go test ./tests
