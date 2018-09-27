ARG PYTHON_VERSION=2

###
### Stage 0: builder
###
FROM docker.io/python:${PYTHON_VERSION}-alpine3.8 as builder

# first of all, install the runtime deps; this layer can then be used in the
# final stage as well.

RUN apk add --no-cache --virtual .runtime_deps \
        libffi \
        libjpeg-turbo \
        libressl \
        libxslt \
        libpq \
        zlib \
        su-exec

# install the OS build deps, and build wheels for the python libs which have
# slow build steps, as more layers which can be cached independently

RUN apk add --no-cache --virtual .build_deps \
        build-base \
        libffi-dev \
        libjpeg-turbo-dev \
        libressl-dev \
        libxslt-dev \
        linux-headers \
        postgresql-dev \
        zlib-dev

RUN pip install --prefix="/install" --no-warn-script-location \
        cryptography \
        lxml \
        msgpack-python \
        pillow \
        psycopg2 \
        pynacl

# now install synapse and all of the python deps to /install.

COPY . /synapse
RUN pip install --prefix="/install" --no-warn-script-location \
        /synapse

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
