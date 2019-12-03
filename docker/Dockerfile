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

ARG PYTHON_VERSION=3.7.5

###
### Stage 0: builder
###
FROM docker.io/python:${PYTHON_VERSION}-slim as builder

RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
 && rm -rf /var/lib/apt/lists/*

# Build dependencies that are not available as wheels, to speed up rebuilds
RUN pip install --prefix="/install" --no-warn-script-location \
        frozendict \
        jaeger-client \
        opentracing \
        prometheus-client \
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
    libpq5 \
    xmlsec1 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local
COPY ./docker/start.py /start.py
COPY ./docker/conf /conf

# Validate that it is able to import
RUN python -m synapse.app.homeserver --version

VOLUME ["/data"]

EXPOSE 8008/tcp 8009/tcp 8448/tcp

ENTRYPOINT ["/start.py"]
