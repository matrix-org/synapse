#!/bin/bash

set -ex

cd $(dirname "$0")/..

docker run --rm -it -v $( pwd ):/io quay.io/pypa/manylinux2014_x86_64 bash /io/scripts-dev/build_wheels_inner.sh
