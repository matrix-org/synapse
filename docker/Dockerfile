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
# There is an optional BASE_IMAGE build argument which sets the
# base image being used, this must be a debian derivative with
# python already installed.
# e.g pyston/slim:2.3.3 or docker.io/python:3.9-slim (default)
#
#    DOCKER_BUILDKIT=1 docker build -f docker/Dockerfile --build-arg BASE_IMAGE=pyston/slim:2.3.3 .
#

# Irritatingly, there is no blessed guide on how to distribute an application with its
# poetry-managed environment in a docker image. We have opted for
# `poetry export | pip install -r /dev/stdin`, but there are known bugs in
# in `poetry export` whose fixes (scheduled for poetry 1.2) have yet to be released.
# In case we get bitten by those bugs in the future, the recommendations here might
# be useful:
#     https://github.com/python-poetry/poetry/discussions/1879#discussioncomment-216865
#     https://stackoverflow.com/questions/53835198/integrating-python-poetry-with-docker?answertab=scoredesc



ARG BASE_IMAGE=docker.io/python:3.9-slim

###
### Stage 0: builder
###
FROM $BASE_IMAGE as builder

# RUN --mount is specific to buildkit and is documented at
# https://github.com/moby/buildkit/blob/master/frontend/dockerfile/docs/syntax.md#build-mounts-run---mount.
# Here we use it to set up a cache for apt (and below for pip), to improve
# rebuild speeds on slow connections.
RUN \
   --mount=type=cache,target=/var/cache/apt,sharing=locked \
   --mount=type=cache,target=/var/lib/apt,sharing=locked \
 apt-get update && apt-get install -y \
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
    rustc \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*


# We use a specific commit from poetry's master branch instead of our usual 1.1.12,
# to incorporate fixes to some bugs in `poetry export`. This commit corresponds to
#    https://github.com/python-poetry/poetry/pull/5156 and
#    https://github.com/python-poetry/poetry/issues/5141 ;
# without it, we generate a requirements.txt with incorrect environment markers,
# which causes necessary packages to be omitted when we `pip install`.
#
# NB: In poetry 1.2 `poetry export` will be moved into a plugin; we'll need to also
# pip install poetry-plugin-export (https://github.com/python-poetry/poetry-plugin-export).
RUN --mount=type=cache,target=/root/.cache/pip \
  pip install --prefix="/poetry" --no-warn-script-location \
    "poetry-core==1.1.0a7" "git+https://github.com/python-poetry/poetry.git@fb13b3a676f476177f7937ffa480ee5cff9a90a5"

WORKDIR /synapse

# Copy just what we need to run `poetry export`...
COPY pyproject.toml poetry.lock /synapse/

RUN PYTHONPATH=$(echo /poetry/lib/*/site-packages/) /poetry/bin/poetry export --extras all -o /synapse/requirements.txt

# To speed up rebuilds, install all of the dependencies before we copy over
# the whole synapse project, so that this layer in the Docker cache can be
# used while you develop on the source
#
# This is aiming at installing the `[tool.poetry.depdendencies]` from pyproject.toml.
RUN --mount=type=cache,target=/root/.cache/pip \
  pip install --prefix="/install" --no-deps --no-warn-script-location -r /synapse/requirements.txt

# Copy over the rest of the synapse source code.
COPY synapse /synapse/synapse/
# ... and what we need to `pip install`.
COPY README.rst /synapse/

# Install the synapse package itself.
RUN pip install --prefix="/install" --no-deps --no-warn-script-location /synapse

###
### Stage 1: runtime
###
FROM $BASE_IMAGE

LABEL org.opencontainers.image.url='https://matrix.org/docs/projects/server/synapse'
LABEL org.opencontainers.image.documentation='https://github.com/matrix-org/synapse/blob/master/docker/README.md'
LABEL org.opencontainers.image.source='https://github.com/matrix-org/synapse.git'
LABEL org.opencontainers.image.licenses='Apache-2.0'

RUN \
   --mount=type=cache,target=/var/cache/apt,sharing=locked \
   --mount=type=cache,target=/var/lib/apt,sharing=locked \
  apt-get update && apt-get install -y \
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