FROM python:2-alpine

RUN apk add --no-cache --virtual .nacl_deps build-base libffi-dev zlib-dev openssl-dev libjpeg-turbo-dev linux-headers

COPY synapse /usr/local/src/synapse
COPY setup.py setup.cfg README.rst synctl /usr/local/src/

RUN cd /usr/local/src \
 && pip install --upgrade --process-dependency-links . \
 && rm -rf setup.py setup.cfg synapse

COPY contrib/docker /

VOLUME ["/data"]

ENTRYPOINT ["/start.py"]
