#!/bin/bash

# Build the Debian packages using Docker images.
#
# This script builds the Docker images and then executes them sequentially, each
# one building a Debian package for the targeted operating system. It is
# designed to be a "single command" to produce all the images.

set -ex

cd `dirname $0`

# Make the dir where the debs will live
mkdir -p ../debs

# Build each OS image;
for i in debian:stretch debian:sid ubuntu:xenial ubuntu:bionic ubuntu:cosmic;
do
    TAG=$(echo ${i} | cut -d ":" -f 2)
    docker build --tag dh-venv-builder:${TAG} --build-arg distro=${i} -f Dockerfile-dhvirtualenv .
    docker run -it --rm --volume=$(pwd)/../\:/synapse/source:ro --volume=$(pwd)/../debs:/debs dh-venv-builder:${TAG}
done


# Make the debs and the Debian directory owned by the current user, not root, so
# that it can be `git clean`ed without problems.
sudo chown $(id -u):$(id -g) -R ../debs/
