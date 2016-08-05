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
python synapse/python_dependencies.py | xargs -n1 $TOX_BIN/pip install
$TOX_BIN/pip install lxml
$TOX_BIN/pip install psycopg2
