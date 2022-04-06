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

ARG PYTHON_VERSION=3.9

###
### Stage 0: builder
###
FROM docker.io/python:${PYTHON_VERSION}-slim as builder

# Irritatingly, there is no blessed guide on how to distribute an application with its
# poetry-managed environment in a docker image. We have opted for
# `poetry export | pip install -r /dev/stdin`, but there are known bugs in
# in `poetry export` whose fixes (scheduled for poetry 1.2) have yet to be released.
# In case we get bitten by those bugs in the future, the recommendations here might
# be useful:
#     https://github.com/python-poetry/poetry/discussions/1879#discussioncomment-216865
#     https://stackoverflow.com/questions/53835198/integrating-python-poetry-with-docker?answertab=scoredesc

# RUN --mount is specific to buildkit and is documented at
# https://github.com/moby/buildkit/blob/master/frontend/dockerfile/docs/syntax.md#build-mounts-run---mount.
# Here we use it to set up a cache for pip (below, for apt and poetry), to improve
# rebuild speeds on slow connections.
# We install poetry as --user so that it doesn't end up in the system-wide python
# installation. That gets copied later into the runtime image.
RUN --mount=type=cache,target=/root/.cache/pip \
  pip install --user poetry==1.1.12

# install the OS build deps
RUN \
   --mount=type=cache,target=/var/cache/apt,sharing=locked \
   --mount=type=cache,target=/var/lib/apt,sharing=locked \
 apt-get update && apt-get install -y \
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

WORKDIR /synapse

# Copy just what we need to run `poetry export`...
COPY pyproject.toml poetry.lock README.rst /synapse/

RUN /root/.local/bin/poetry export --extras all -o /synapse/requirements.txt

# To speed up rebuilds, install all of the dependencies before we copy over
# the whole synapse project, so that this layer in the Docker cache can be
# used while you develop on the source
#
# This is aiming at installing the `[tool.poetry.depdendencies]` from pyproject.toml.
RUN --mount=type=cache,target=/root/.cache/pip \
  pip install --prefix="/install" --no-warn-script-location -r /synapse/requirements.txt

# Copy over the rest of the synapse source code.
COPY synapse /synapse/synapse/
# ... and the setuptools metadata needed to `pip install`.
# TODO: once pyproject.toml declares poetry-core as its build system,
# we can remove this COPY statement.
COPY setup.py MANIFEST.in /synapse/

# Install the synapse package itself.
RUN pip install --prefix="/install" --no-deps --no-warn-script-location /synapse

###
### Stage 1: runtime
###

FROM docker.io/python:${PYTHON_VERSION}-slim

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

COPY --from=builder /install /usr/local
COPY ./docker/start.py /start.py
COPY ./docker/conf /conf

EXPOSE 8008/tcp 8009/tcp 8448/tcp

ENTRYPOINT ["/start.py"]

HEALTHCHECK --start-period=5s --interval=15s --timeout=5s \
    CMD curl -fSs http://localhost:8008/health || exit 1
