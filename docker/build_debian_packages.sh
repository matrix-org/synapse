#!/bin/bash

# Build the Debian packages using Docker images.
#
# This script builds the Docker images and then executes them sequentially, each
# one building a Debian package for the targeted operating system. It is
# designed to be a "single command" to produce all the images.

# Make the dir where the debs will live
mkdir -p ../debs

# Build each OS image and then build the package. It gets copied out as part of
# the process.
for i in xenial bionic cosmic;
do
    docker build --tag dh-venv-builder:$(i) --build-arg distro=ubuntu:$(i) -f Dockerfile-dhvirtualenv .
    docker run -it --rm --volume=$(pwd)/../\:/synapse/build dh-venv-builder:$(i)
done

# Make the debs and the Debian directory owned by the current user, not root, so
# that it can be `git clean`ed without problems.
sudo chown $(id -u):$(id -g) -R ../debs/ ../debian/
