#!/bin/bash

mkdir -p ../debs

docker build --tag dh-venv-builder:bionic --build-arg distro=ubuntu:bionic -f Dockerfile-dhvirtualenv .
docker build --tag dh-venv-builder:stretch --build-arg distro=debian:stretch -f Dockerfile-dhvirtualenv .

docker run -it --rm --volume=$(pwd)/../\:/build dh-venv-builder:bionic
docker run -it --rm --volume=$(pwd)/../\:/build dh-venv-builder:stretch