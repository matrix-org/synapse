# Copyright 2017 Vector Creations Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM phusion/baseimage:0.9.22

COPY ./ /synapse/source/

RUN apt-get update -y \
    && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y \
        build-essential \
        libffi-dev \
        libjpeg-dev \
        libpq-dev \
        libssl-dev \
        libxslt1-dev \
        python-pip \
        python-setuptools \
        python-virtualenv \
        python2.7-dev \
        sqlite3 \
    && virtualenv -p python2.7 /synapse \
    && . /synapse/bin/activate \
    && pip install --upgrade pip \
    && pip install --upgrade setuptools \
    && pip install --upgrade psycopg2 \
    && cd /synapse/source \
    && pip install --upgrade ./ \
    && cd / \
    && rm -rf /synapse/source \
    && apt-get autoremove -y \
        build-essential \
        libffi-dev \
        libjpeg-dev \
        libpq-dev \
        libssl-dev \
        libxslt1-dev \
        python2.7-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY docker/rootfs/ /

VOLUME /synapse/config/
VOLUME /synapse/data/

CMD ["/sbin/my_init"]
