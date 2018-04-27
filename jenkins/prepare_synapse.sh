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

TOX_BIN=$TOX_DIR/py27/bin

# cryptography 2.2 requires setuptools >= 18.5.
#
# older versions of virtualenv (?) give us a virtualenv with the same version
# of setuptools as is installed on the system python (and tox runs virtualenv
# under python3, so we get the version of setuptools that is installed on that).
#
# anyway, make sure that we have a recent enough setuptools.
$TOX_BIN/pip install 'setuptools>=18.5'

# we also need a semi-recent version of pip, because old ones fail to install
# the "enum34" dependency of cryptography.
$TOX_BIN/pip install 'pip>=10'

{ python synapse/python_dependencies.py
  echo lxml psycopg2
} | xargs $TOX_BIN/pip install
