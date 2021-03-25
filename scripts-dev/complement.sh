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
wget -N https://github.com/matrix-org/complement/archive/master.tar.gz
tar -xzf master.tar.gz
cd complement-master

# Build the Synapse image from Complement, based on the above image we just built
docker build -t complement-synapse -f dockerfiles/Synapse.Dockerfile ./dockerfiles

# Run the tests on the resulting image!
COMPLEMENT_BASE_IMAGE=complement-synapse go test -v -count=1 ./tests
