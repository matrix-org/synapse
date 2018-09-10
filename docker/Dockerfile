FROM docker.io/python:2-alpine3.8

COPY . /synapse

RUN apk add --no-cache --virtual .build_deps \
        build-base \
        libffi-dev \
        libjpeg-turbo-dev \
        libressl-dev \
        libxslt-dev \
        linux-headers \
        postgresql-dev \
        zlib-dev \
 && cd /synapse \
 && apk add --no-cache --virtual .runtime_deps \
 	libffi \
        libjpeg-turbo \
	libressl \
	libxslt \
	libpq \
	zlib \
	su-exec \
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
        synapse \
 && apk del .build_deps
 
VOLUME ["/data"]

EXPOSE 8008/tcp 8448/tcp

ENTRYPOINT ["/start.py"]
