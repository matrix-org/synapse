FROM python:2-alpine

RUN apk add --no-cache --virtual .nacl_deps build-base libffi-dev zlib-dev openssl-dev libjpeg-turbo-dev linux-headers postgresql-dev

COPY . /synapse

# A wheel cache may be provided in ./cache for faster build
RUN cd /synapse \
 && pip install --upgrade pip setuptools psycopg2 \
 && mkdir -p /synapse/cache \
 && pip install -f /synapse/cache --upgrade --process-dependency-links . \
 && mv /synapse/contrib/docker/* / \
 && rm -rf setup.py setup.cfg synapse

VOLUME ["/data"]

EXPOSE 8448

ENTRYPOINT ["/start.py"]
