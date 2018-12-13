#!/bin/bash

# The script to build the Debian package, as ran inside the Docker image.

set -ex

# We need to build a newer dh_virtualenv on older OSes like Xenial.
if [[ $(lsb_release -c -s) == 'xenial' ]];
then
    mkdir -p /tmp/dhvenv
    cd /tmp/dhvenv
    wget https://github.com/spotify/dh-virtualenv/archive/1.1.tar.gz
    tar xvf 1.1.tar.gz
    cd dh-virtualenv-1.1/
    env DEBIAN_FRONTEND=noninteractive mk-build-deps -ri -t "apt-get -yqq --no-install-recommends -o Dpkg::Options::=--force-unsafe-io"
    dpkg-buildpackage -us -uc -b
    cd /tmp/dhvenv
    apt-get install -yqq ./dh-virtualenv_1.1-1_all.deb
    cd /synapse/build
fi

ls -la ../

dpkg-buildpackage -us -uc -b

cp ../*.deb /synapse/build/debs
