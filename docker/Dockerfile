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
# `poetry export | pip install -r /dev/stdin`, but beware: we have experienced bugs in
# in `poetry export` in the past.

ARG PYTHON_VERSION=3.11

###
### Stage 0: generate requirements.txt
###
# We hardcode the use of Debian bookworm here because this could change upstream
# and other Dockerfiles used for testing are expecting bookworm.
FROM docker.io/library/python:${PYTHON_VERSION}-slim-bookworm as requirements

# RUN --mount is specific to buildkit and is documented at
# https://github.com/moby/buildkit/blob/master/frontend/dockerfile/docs/syntax.md#build-mounts-run---mount.
# Here we use it to set up a cache for apt (and below for pip), to improve
# rebuild speeds on slow connections.
RUN \
  --mount=type=cache,target=/var/cache/apt,sharing=locked \
  --mount=type=cache,target=/var/lib/apt,sharing=locked \
  apt-get update -qq && apt-get install -yqq \
  build-essential curl git libffi-dev libssl-dev pkg-config \
  && rm -rf /var/lib/apt/lists/*

# Install rust and ensure its in the PATH.
# (Rust may be needed to compile `cryptography`---which is one of poetry's
# dependencies---on platforms that don't have a `cryptography` wheel.
ENV RUSTUP_HOME=/rust
ENV CARGO_HOME=/cargo
ENV PATH=/cargo/bin:/rust/bin:$PATH
RUN mkdir /rust /cargo

RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --default-toolchain stable --profile minimal

# arm64 builds consume a lot of memory if `CARGO_NET_GIT_FETCH_WITH_CLI` is not
# set to true, so we expose it as a build-arg.
ARG CARGO_NET_GIT_FETCH_WITH_CLI=false
ENV CARGO_NET_GIT_FETCH_WITH_CLI=$CARGO_NET_GIT_FETCH_WITH_CLI

# We install poetry in its own build stage to avoid its dependencies conflicting with
# synapse's dependencies.
RUN --mount=type=cache,target=/root/.cache/pip \
  pip install --user "poetry==1.3.2"

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
FROM docker.io/library/python:${PYTHON_VERSION}-slim-bookworm as builder

# install the OS build deps
RUN \
  --mount=type=cache,target=/var/cache/apt,sharing=locked \
  --mount=type=cache,target=/var/lib/apt,sharing=locked \
  apt-get update -qq && apt-get install -yqq \
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
  libicu-dev \
  pkg-config \
  && rm -rf /var/lib/apt/lists/*


# Install rust and ensure its in the PATH
ENV RUSTUP_HOME=/rust
ENV CARGO_HOME=/cargo
ENV PATH=/cargo/bin:/rust/bin:$PATH
RUN mkdir /rust /cargo

RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --default-toolchain stable --profile minimal


# arm64 builds consume a lot of memory if `CARGO_NET_GIT_FETCH_WITH_CLI` is not
# set to true, so we expose it as a build-arg.
ARG CARGO_NET_GIT_FETCH_WITH_CLI=false
ENV CARGO_NET_GIT_FETCH_WITH_CLI=$CARGO_NET_GIT_FETCH_WITH_CLI

# To speed up rebuilds, install all of the dependencies before we copy over
# the whole synapse project, so that this layer in the Docker cache can be
# used while you develop on the source
#
# This is aiming at installing the `[tool.poetry.depdendencies]` from pyproject.toml.
COPY --from=requirements /synapse/requirements.txt /synapse/
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
RUN --mount=type=cache,target=/synapse/target,sharing=locked \
  --mount=type=cache,target=${CARGO_HOME}/registry,sharing=locked \
  if [ -z "$TEST_ONLY_IGNORE_POETRY_LOCKFILE" ]; then \
  pip install --prefix="/install" --no-deps --no-warn-script-location /synapse[all]; \
  else \
  pip install --prefix="/install" --no-warn-script-location /synapse[all]; \
  fi

###
### Stage 2: runtime
###

FROM docker.io/library/python:${PYTHON_VERSION}-slim-bookworm

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
  libwebp7 \
  xmlsec1 \
  libjemalloc2 \
  libicu72 \
  libssl-dev \
  openssl \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local
COPY ./docker/start.py /start.py
COPY ./docker/conf /conf

EXPOSE 8008/tcp 8009/tcp 8448/tcp

ENTRYPOINT ["/start.py"]

HEALTHCHECK --start-period=5s --interval=15s --timeout=5s \
  CMD curl -fSs http://localhost:8008/health || exit 1
