#!/bin/bash

# Builds wheels when run in a manylinux container

set -ex

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
export PATH="$HOME/.cargo/bin:$PATH"

# Compile wheels
for PYBIN in /opt/python/cp{37,38,39,310}*/bin; do
    rm -rf /io/build/

    # Until https://github.com/python-poetry/poetry/pull/5401 lands we need to
    # manually install setuptools_rust
    rm -rf /tmp/venv
    "${PYBIN}/python" -m venv /tmp/venv
    source /tmp/venv/bin/activate

    pip install -U poetry setuptools_rust
    cd /io
    poetry build -f wheel
done

# Bundle external shared libraries into the wheels
for whl in /io/dist/*{cp37,cp38,cp39,cp310}*.whl; do
    auditwheel repair "$whl" -w /io/dist/
done

# Install packages and test
for PYBIN in /opt/python/cp{37,38,39,310}*/bin; do
    "${PYBIN}/pip" install synapse -f /io/dist/
done
