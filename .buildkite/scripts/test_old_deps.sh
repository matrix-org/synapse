#!/bin/bash

# this script is run by buildkite in a plain `xenial` container; it installs the
# minimal requirements for tox and hands over to the py35-old tox environment.

set -ex

apt-get update
apt-get install -y python3.5 python3.5-dev python3-pip libxml2-dev libxslt-dev zlib1g-dev

# workaround for https://github.com/jaraco/zipp/issues/40
python3.5 -m pip install setuptools

python3.5 -m pip install tox

export LANG="C.UTF-8"

exec tox -e py35-old,combine
