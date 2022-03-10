#!/usr/bin/env bash
# this script is run by GitHub Actions in a plain `focal` container; it installs the
# minimal requirements for tox and hands over to the py3-old tox environment.

# Prevent tzdata from asking for user input
export DEBIAN_FRONTEND=noninteractive

set -ex

apt-get update
apt-get install -y \
        python3 python3-dev python3-pip python3-venv \
        libxml2-dev libxslt-dev xmlsec1 zlib1g-dev tox libjpeg-dev libwebp-dev

export LANG="C.UTF-8"

# Prevent virtualenv from auto-updating pip to an incompatible version
export VIRTUALENV_NO_DOWNLOAD=1

# I'd prefer to use something like this
#   https://github.com/python-poetry/poetry/issues/3527
#   https://github.com/pypa/pip/issues/8085
# rather than this sed script. But that's an Opinion.

# patch the project definitions in-place
# replace all lower bounds with exact bounds
# delete all lines referring to psycopg2 --- so no postgres support

# but make the pyopenssl 17.0, which can work against an
  #    # OpenSSL 1.1 compiled cryptography (as older ones don't compile on Travis).
sed -i -e "s/[~>]=/==/g" -e "/psycopg2/d" pyproject.toml
pip install -e .[all]