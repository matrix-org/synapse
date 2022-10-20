# syntax=docker/dockerfile:1
# Dockerfile to build the matrixdotorg/synapse docker images.
#
# Note that it uses features which are only available in BuildKit - see
# https://docs.docker.com/go/buildkit/ for more information.
#
# To build the image, run `docker build` command from the root of the
# synapse repository:
#
#    DOCKER_BUILDKIT=1 docker build -f docker/Dockerfile .
#
# There is an optional PYTHON_VERSION build argument which sets the
# version of python to build against: for example:
#
#    DOCKER_BUILDKIT=1 docker build -f docker/Dockerfile --build-arg PYTHON_VERSION=3.10 .
#

# Irritatingly, there is no blessed guide on how to distribute an application with its
# poetry-managed environment in a docker image. We have opted for
# `poetry export | pip install -r /dev/stdin`, but there are known bugs in
# in `poetry export` whose fixes (scheduled for poetry 1.2) have yet to be released.
# In case we get bitten by those bugs in the future, the recommendations here might
# be useful:
#     https://github.com/python-poetry/poetry/discussions/1879#discussioncomment-216865
#     https://stackoverflow.com/questions/53835198/integrating-python-poetry-with-docker?answertab=scoredesc


ARG PYTHON_VERSION=3.9
ARG BASE_IMAGE=docker.io/python:${PYTHON_VERSION}-slim-bullseye


###
### Stage 0: generate requirements.txt
###
# We hardcode the use of Debian bullseye here because this could change upstream
# and other Dockerfiles used for testing are expecting bullseye.
FROM $BASE_IMAGE as requirements

# RUN --mount is specific to buildkit and is documented at
# https://github.com/moby/buildkit/blob/master/frontend/dockerfile/docs/syntax.md#build-mounts-run---mount.
# Here we use it to set up a cache for apt (and below for pip), to improve
# rebuild speeds on slow connections.
RUN \
   --mount=type=cache,target=/var/cache/apt,sharing=locked \
   --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update -qq && apt-get install -yqq \
      build-essential cargo git libffi-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# We install poetry in its own build stage to avoid its dependencies conflicting with
# synapse's dependencies.
RUN --mount=type=cache,target=/root/.cache/pip \
  pip install --user "poetry==1.2.0"

WORKDIR /synapse

# Copy just what we need to run `poetry export`...
COPY pyproject.toml poetry.lock /synapse/


# If specified, we won't verify the hashes of dependencies.
# This is only needed if the hashes of dependencies cannot be checked for some
# reason, such as when a git repository is used directly as a dependency.
ARG TEST_ONLY_SKIP_DEP_HASH_VERIFICATION

# If specified, we won't use the Poetry lockfile.
# Instead, we'll just install what a regular `pip install` would from PyPI.
ARG TEST_ONLY_IGNORE_POETRY_LOCKFILE

# Export the dependencies, but only if we're actually going to use the Poetry lockfile.
# Otherwise, just create an empty requirements file so that the Dockerfile can
# proceed.
RUN if [ -z "$TEST_ONLY_IGNORE_POETRY_LOCKFILE" ]; then \
    /root/.local/bin/poetry export --extras all -o /synapse/requirements.txt ${TEST_ONLY_SKIP_DEP_HASH_VERIFICATION:+--without-hashes}; \
  else \
    touch /synapse/requirements.txt; \
  fi

###
### Stage 1: builder
###
FROM $BASE_IMAGE as builder

# install the OS build deps
RUN \
   --mount=type=cache,target=/var/cache/apt,sharing=locked \
   --mount=type=cache,target=/var/lib/apt,sharing=locked \
 apt-get update -qq && apt-get install -yqq \
    git \
    build-essential \
    libffi-dev \
    libjpeg-dev \
    libpq-dev \
    libssl-dev \
    libwebp-dev \
    libxml++2.6-dev \
    libxslt1-dev \
    openssl \
    zlib1g-dev \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install rust and ensure its in the PATH
ENV RUSTUP_HOME=/rust
ENV CARGO_HOME=/cargo
ENV PATH=/cargo/bin:/rust/bin:$PATH
RUN mkdir /rust /cargo

RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --default-toolchain stable

# arm64 builds consume a lot of memory if `CARGO_NET_GIT_FETCH_WITH_CLI` is not
# set to true, so we expose it as a build-arg.
ARG CARGO_NET_GIT_FETCH_WITH_CLI=false
ENV CARGO_NET_GIT_FETCH_WITH_CLI=$CARGO_NET_GIT_FETCH_WITH_CLI

# Beeper: install shared secret authenticator
RUN pip install --prefix="/install" --no-deps --no-warn-script-location \
   'git+https://github.com/devture/matrix-synapse-shared-secret-auth@e178353ec87c56e0169dd04466d4769da5ed9c46#egg=shared_secret_authenticator'

# To speed up rebuilds, install all of the dependencies before we copy over
# the whole synapse project, so that this layer in the Docker cache can be
# used while you develop on the source
#
# This is aiming at installing the `[tool.poetry.depdendencies]` from pyproject.toml.
COPY --from=requirements /synapse/requirements.txt /synapse/requirements.txt

# Beeper: pyston fixes
# For some utterly stupid reasons pip under pyston doesn't seem capable of upgrading setuptools at the same time as
# installing packages that use it, so we just hack past it by ignoring the pinned setuptools version. Ugh.
RUN cp /synapse/requirements.txt /synapse/requirements-with-setuptools.txt && rm -f /synapse/requirements.txt
RUN cat /synapse/requirements-with-setuptools.txt | grep -v "setuptools==" > /synapse/requirements.txt
# pyston base image pip version isn't high enough
RUN pip install pip -U

RUN --mount=type=cache,target=/root/.cache/pip \
  pip install --prefix="/install" --no-deps --no-warn-script-location -r /synapse/requirements.txt

# Copy over the rest of the synapse source code.
COPY synapse /synapse/synapse/
COPY rust /synapse/rust/
# ... and what we need to `pip install`.
COPY pyproject.toml README.rst build_rust.py Cargo.toml Cargo.lock /synapse/

# Repeat of earlier build argument declaration, as this is a new build stage.
ARG TEST_ONLY_IGNORE_POETRY_LOCKFILE

# Install the synapse package itself.
# If we have populated requirements.txt, we don't install any dependencies
# as we should already have those from the previous `pip install` step.
RUN if [ -z "$TEST_ONLY_IGNORE_POETRY_LOCKFILE" ]; then \
    pip install --prefix="/install" --no-deps --no-warn-script-location /synapse[all]; \
  else \
    pip install --prefix="/install" --no-warn-script-location /synapse[all]; \
  fi

# Beeper: pyston fixes
# For *reasons* installing synapse with pip under pyston leaves the rust shared object in the
# build directory not the /install/lib/... directory.
RUN if [ -f "/synapse/build/lib/synapse/synapse_rust.abi3.so" ]; then \
    mv /synapse/build/lib/synapse/synapse_rust.abi3.so /install/lib/*/site-packages/synapse/; \
  fi

###
### Stage 2: runtime
###

FROM $BASE_IMAGE

LABEL org.opencontainers.image.url='https://matrix.org/docs/projects/server/synapse'
LABEL org.opencontainers.image.documentation='https://github.com/matrix-org/synapse/blob/master/docker/README.md'
LABEL org.opencontainers.image.source='https://github.com/matrix-org/synapse.git'
LABEL org.opencontainers.image.licenses='Apache-2.0'

RUN \
   --mount=type=cache,target=/var/cache/apt,sharing=locked \
   --mount=type=cache,target=/var/lib/apt,sharing=locked \
  apt-get update -qq && apt-get install -yqq \
    curl \
    gosu \
    libjpeg62-turbo \
    libpq5 \
    libwebp6 \
    xmlsec1 \
    libjemalloc2 \
    libssl-dev \
    openssl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install/bin /usr/local/bin
# Copy the python site-packages into /install instead of /usr/local/lib as some environments use different paths
# e.g pyston using /usr/lib, so we instead specify a PYTHONPATH environment variable to make everyone happy.
COPY --from=builder /install/lib/*/site-packages /install
ENV PYTHONPATH="/install"

COPY ./docker/start.py /start.py
COPY ./docker/conf /conf

EXPOSE 8008/tcp 8009/tcp 8448/tcp

ENTRYPOINT ["/start.py"]

HEALTHCHECK --start-period=5s --interval=15s --timeout=5s \
    CMD curl -fSs http://localhost:8008/health || exit 1
