#! /bin/bash

cd "`dirname $0`/.."

TOX_DIR=$WORKSPACE/.tox

mkdir -p $TOX_DIR

if ! [ $TOX_DIR -ef .tox ]; then
    ln -s "$TOX_DIR" .tox
fi

# set up the virtualenv
tox -e py27 --notest -v

TOX_BIN=$TOX_DIR/py27/bin
$TOX_BIN/pip install setuptools
{ python synapse/python_dependencies.py
  echo lxml psycopg2
} | xargs $TOX_BIN/pip install
