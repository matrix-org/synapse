FROM docker.io/python:2-alpine3.7

RUN apk add --no-cache --virtual .nacl_deps su-exec build-base libffi-dev zlib-dev libressl-dev libjpeg-turbo-dev linux-headers postgresql-dev

COPY . /synapse

# A wheel cache may be provided in ./cache for faster build
RUN cd /synapse \
 && pip install --upgrade pip setuptools psycopg2 \
 && mkdir -p /synapse/cache \
 && pip install -f /synapse/cache --upgrade --process-dependency-links . \
 && mv /synapse/contrib/docker/start.py /synapse/contrib/docker/conf / \
 && rm -rf setup.py setup.cfg synapse

VOLUME ["/data"]

EXPOSE 8008/tcp 8448/tcp

ENTRYPOINT ["/start.py"]
