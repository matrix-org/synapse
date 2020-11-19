# Dockerfile to build the matrixdotorg/synapse docker images.
#
# To build the image, run `docker build` command from the root of the
# synapse repository:
#
#    docker build -f docker/Dockerfile .
#
# There is an optional PYTHON_VERSION build argument which sets the
# version of python to build against: for example:
#
#    docker build -f docker/Dockerfile --build-arg PYTHON_VERSION=3.6 .
#

ARG PYTHON_VERSION=3.8

###
### Stage 0: builder
###
FROM docker.io/python:${PYTHON_VERSION}-slim as builder

# install the OS build deps
RUN apt-get update && apt-get install -y \
    build-essential \
    libffi-dev \
    libjpeg-dev \
    libpq-dev \
    libssl-dev \
    libwebp-dev \
    libxml++2.6-dev \
    libxslt1-dev \
    zlib1g-dev \
 && rm -rf /var/lib/apt/lists/*

# Build dependencies that are not available as wheels, to speed up rebuilds
RUN pip install --prefix="/install" --no-warn-script-location \
        frozendict \
        jaeger-client \
        opentracing \
        # Match the version constraints of Synapse
        "prometheus_client>=0.4.0,<0.9.0" \
        psycopg2 \
        pycparser \
        pyrsistent \
        pyyaml \
        simplejson \
        threadloop \
        thrift

# now install synapse and all of the python deps to /install.
COPY synapse /synapse/synapse/
COPY scripts /synapse/scripts/
COPY MANIFEST.in README.rst setup.py synctl /synapse/

RUN pip install --prefix="/install" --no-warn-script-location \
        /synapse[all]

###
### Stage 1: runtime
###

FROM docker.io/python:${PYTHON_VERSION}-slim

RUN apt-get update && apt-get install -y \
    curl \
    gosu \
    libjpeg62-turbo \
    libpq5 \
    libwebp6 \
    xmlsec1 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local
COPY ./docker/start.py /start.py
COPY ./docker/conf /conf

VOLUME ["/data"]

EXPOSE 8008/tcp 8009/tcp 8448/tcp

ENTRYPOINT ["/start.py"]

HEALTHCHECK --interval=1m --timeout=5s \
  CMD curl -fSs http://localhost:8008/health || exit 1
