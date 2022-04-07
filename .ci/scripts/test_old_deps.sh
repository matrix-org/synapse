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

# Patch the project definitions in-place:
# - Replace all lower and tilde bounds with exact bounds
# - Make the pyopenssl 17.0, which is the oldest version that works with
#   a `cryptography` compiled against OpenSSL 1.1.
# - Delete all lines referring to psycopg2 --- so no testing of postgres support.
# - Omit systemd: we're not logging to journal here.

# TODO: we should also replace caret bounds, see
#    https://python-poetry.org/docs/dependency-specification/#version-constraints
# We don't use these yet, but they are the default bound used when you `poetry add` from
# the commandline, rather than editing pyproject.toml directly.
# The sed expression 's/\^/==/g' ought to do the trick. But it would also change
# `python = "^3.7"` to `python = "==3.7"`, which would mean we fail because olddeps
# runs on 3.8 (#12343).

# TODO: I'd prefer to use something like this
#   https://github.com/python-poetry/poetry/issues/3527
#   https://github.com/pypa/pip/issues/8085
# rather than this sed script.

sed -i-backup \
   -e "s/[~>]=/==/g" \
   -e "/psycopg2/d" \
   -e 's/pyOpenSSL = "==16.0.0"/pyOpenSSL = "==17.0.0"/' \
   -e '/psycopg2/d' \
   -e '/systemd/d' \
   pyproject.toml

# TODO: once pyproject.toml uses poetry-core as its build-system, we may be able to
# simply `pip install .[all, test]` and run trial directly. (We would have to convince
# ourselves that pip will refuse to install if the olddeps are incompatible with each
# other: folklore contends that pip's resolver is more lax than poetry's.)
#
# Until then, setuptools is the build system. That means we need to use `poetry` to
# do the installation. `poetry lock` fails because of incompatibilities between dev
# dependencies and old deps. Workaround this by removing dev dependencies entirely.

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

pipx install poetry==1.1.12
~/.local/bin/poetry lock

echo "::group::Patched pyproject.toml"
cat pyproject.toml
echo "::endgroup::"
echo "::group::Lockfile after patch"
cat poetry.lock
echo "::endgroup::"

~/.local/bin/poetry install -E "all test"
~/.local/bin/poetry run trial --jobs=2 tests
