ARG PYTHON_VERSION=3

###
### Stage 0: builder
###
FROM docker.io/python:${PYTHON_VERSION}-slim-stretch as builder

# install the OS build deps

RUN apt-get update && apt-get install -y \
        build-essential \
        libffi-dev \
        sqlite3 \
        libssl-dev \
        libjpeg-dev \
        libxslt1-dev \
        libxml2-dev \
        libpq-dev

# for ksm_preload
RUN apt-get install -y \
        git \
        cmake

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
        lxml \
        psycopg2-binary \
        /synapse

# N.B. to work, this needs:
# echo 1 > /sys/kernel/mm/ksm/run
# echo 31250 > /sys/kernel/mm/ksm/pages_to_scan # 128MB of 4KB pages at a time
# echo 10000 > /sys/kernel/mm/ksm/pages_to_scan # 40MB of pages at a time
# ...to be run in the Docker host

RUN git clone https://github.com/unbrice/ksm_preload && \
    cd ksm_preload && \
    cmake . && \
    make && \
    cp libksm_preload.so /install/lib

###
### Stage 1: runtime
###

FROM docker.io/python:${PYTHON_VERSION}-slim-stretch

RUN apt-get update && apt-get install -y \
    procps \
    net-tools \
    iproute2 \
    tcpdump \
    traceroute \
    mtr-tiny \
    inetutils-ping \
    less \
    lsof \
    supervisor

# for topologiser
RUN pip install flask

COPY --from=builder /install /usr/local
COPY ./docker/start.py /start.py
COPY ./docker/conf /conf
COPY ./docker/proxy/proxy /proxy
COPY ./docker/proxy/maps /maps
COPY ./docker/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

VOLUME ["/data"]

EXPOSE 8008/tcp 8448/tcp 3000/tcp 5683/udp

ENV LD_PRELOAD=/usr/local/lib/libksm_preload.so

# default is 32768 (8 4KB pages)
ENV KSMP_MERGE_THRESHOLD=16384

ENTRYPOINT ["/usr/bin/supervisord"]
