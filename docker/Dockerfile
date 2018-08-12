FROM docker.io/python:2-alpine3.7

RUN apk add --no-cache --virtual .nacl_deps \
        build-base \
        libffi-dev \
        libjpeg-turbo-dev \
        libressl-dev \
        libxslt-dev \
        linux-headers \
        postgresql-dev \
        su-exec \
        zlib-dev

COPY . /synapse

# A wheel cache may be provided in ./cache for faster build
RUN cd /synapse \
 && pip install --upgrade \
        lxml \
        pip \
        psycopg2 \
        setuptools \
 && mkdir -p /synapse/cache \
 && pip install -f /synapse/cache --upgrade --process-dependency-links . \
 && mv /synapse/docker/start.py /synapse/docker/conf / \
 && rm -rf \
        setup.cfg \
        setup.py \
        synapse

VOLUME ["/data"]

EXPOSE 8008/tcp 8448/tcp

ENTRYPOINT ["/start.py"]
