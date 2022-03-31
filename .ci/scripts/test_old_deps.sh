#!/usr/bin/env bash
# this script is run by GitHub Actions in a plain `focal` container; it
# - installs the minimal system requirements, and poetry;
# - patches the project definition file to refer to old versions only;
# - creates a venv with these old versions using poetry; and finally
# - invokes `trial` to run the tests with old deps.

# Prevent tzdata from asking for user input
export DEBIAN_FRONTEND=noninteractive

set -ex

apt-get update
apt-get install -y \
        python3 python3-dev python3-pip python3-venv pipx \
        libxml2-dev libxslt-dev xmlsec1 zlib1g-dev libjpeg-dev libwebp-dev

export LANG="C.UTF-8"

# Prevent virtualenv from auto-updating pip to an incompatible version
export VIRTUALENV_NO_DOWNLOAD=1

# TODO: in the future, we could use an implementation of
#   https://github.com/python-poetry/poetry/issues/3527
#   https://github.com/pypa/pip/issues/8085
# to select the lowest possible versions, rather than resorting to this sed script.

# patch the project definitions in-place
# replace all lower bounds with exact bounds
# but make the pyopenssl 17.0, which can work against an
# OpenSSL 1.1 compiled cryptography (as older ones don't compile on Travis).
# delete all lines referring to psycopg2 --- so no testing of postgres support
# Omit systemd: we're not logging to journal here.

sed -i-backup \
   -e "s/[~>]=/==/g" \
   -e "/psycopg2/d" \
   -e 's/pyOpenSSL = "==16.0.0"/pyOpenSSL = "==17.0.0"/' \
   -e '/systemd/d' \
   pyproject.toml

# Use poetry to do the installation. This ensures that the versions are all mutually
# compatible (as far the package metadata declares, anyway); pip's package resolver
# is more lax.
#
# Rather than `poetry install --no-dev`, we drop all dev dependencies from the
# toml file. This means we don't have to ensure compatibility between old deps and
# dev tools.

pip install --user toml

REMOVE_DEV_DEPENDENCIES="
import toml
with open('pyproject.toml', 'r') as f:
    data = toml.loads(f.read())

del data['tool']['poetry']['dev-dependencies']

with open('pyproject.toml', 'w') as f:
    toml.dump(data, f)
"
python3 -c "$REMOVE_DEV_DEPENDENCIES"

echo "::group::Patched pyproject.toml"
diff -u pyproject.toml-backup pyproject.toml
echo "::endgroup::"

pipx install poetry==1.1.12
~/.local/bin/poetry lock
~/.local/bin/poetry install -E "all test"
~/.local/bin/poetry run trial -j2 tests
