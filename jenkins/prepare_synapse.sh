#! /bin/bash

set -eux

cd "`dirname $0`/.."

TOX_DIR=$WORKSPACE/.tox

mkdir -p $TOX_DIR

if ! [ $TOX_DIR -ef .tox ]; then
    ln -s "$TOX_DIR" .tox
fi

# set up the virtualenv
tox -e py27 --notest -v
