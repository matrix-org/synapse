ARG PYTHON_VERSION=2

###
### Stage 0: builder
###
FROM docker.io/python:${PYTHON_VERSION}-alpine3.8 as builder

# install the OS build deps

RUN apk add \
        build-base \
        libffi-dev \
        libjpeg-turbo-dev \
        libressl-dev \
        libxslt-dev \
        linux-headers \
        postgresql-dev \
        zlib-dev

# build things which have slow build steps, before we copy synapse, so that
# the layer can be cached.
#
# (we really just care about caching a wheel here, as the "pip install" below
# will install them again.)

RUN pip install --prefix="/install" --no-warn-script-location \
        cryptography \
        msgpack-python \
        pillow \
        pynacl

# now install synapse and all of the python deps to /install.

COPY . /synapse
RUN pip install --prefix="/install" --no-warn-script-location \
        /synapse[all]

###
### Stage 1: runtime
###

FROM docker.io/python:${PYTHON_VERSION}-alpine3.8

RUN apk add --no-cache --virtual .runtime_deps \
        libffi \
        libjpeg-turbo \
        libressl \
        libxslt \
        libpq \
        zlib \
        su-exec

COPY --from=builder /install /usr/local
COPY ./docker/start.py /start.py
COPY ./docker/conf /conf

VOLUME ["/data"]

EXPOSE 8008/tcp 8448/tcp

ENTRYPOINT ["/start.py"]
