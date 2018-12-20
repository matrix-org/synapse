#!/bin/bash

# Build the Debian packages using Docker images.
#
# This script builds the Docker images and then executes them sequentially, each
# one building a Debian package for the targeted operating system. It is
# designed to be a "single command" to produce all the images.
#
# By default, builds for all known distributions, but a list of distributions
# can be passed on the commandline for debugging.

set -ex

cd `dirname $0`

if [ $# -lt 1 ]; then
    DISTS=(
        debian:stretch
        debian:buster
        debian:sid
        ubuntu:xenial
        ubuntu:bionic
        ubuntu:cosmic
    )
else
    DISTS=("$@")
fi

# Make the dir where the debs will live.
#
# Note that we deliberately put this outside the source tree, otherwise we tend
# to get source packages which are full of debs. (We could hack around that
# with more magic in the build_debian.sh script, but that doesn't solve the
# problem for natively-run dpkg-buildpakage).

mkdir -p ../../debs

# Build each OS image;
for i in "${DISTS[@]}"; do
    TAG=$(echo ${i} | cut -d ":" -f 2)
    docker build --tag dh-venv-builder:${TAG} --build-arg distro=${i} -f Dockerfile-dhvirtualenv .
    docker run -it --rm --volume=$(pwd)/../\:/synapse/source:ro --volume=$(pwd)/../../debs:/debs \
           -e TARGET_USERID=$(id -u) \
           -e TARGET_GROUPID=$(id -g) \
           dh-venv-builder:${TAG}
done
