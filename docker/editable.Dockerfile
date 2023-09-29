# syntax=docker/dockerfile:1
# This dockerfile builds an editable install of Synapse.
#
# Used by `complement.sh`. Not suitable for production use.

ARG PYTHON_VERSION=3.9

###
### Stage 0: generate requirements.txt
###
# We hardcode the use of Debian bookworm here because this could change upstream
# and other Dockerfiles used for testing are expecting bookworm.
FROM docker.io/library/python:${PYTHON_VERSION}-slim-bookworm

# Install Rust and other dependencies (stolen from normal Dockerfile)
# install the OS build deps
RUN \
   --mount=type=cache,target=/var/cache/apt,sharing=locked \
   --mount=type=cache,target=/var/lib/apt,sharing=locked \
 apt-get update -qq && apt-get install -yqq \
    build-essential \
    libffi-dev \
    libjpeg-dev \
    libpq-dev \
    libssl-dev \
    libwebp-dev \
    libxml++2.6-dev \
    libxslt1-dev \
    openssl \
    zlib1g-dev \
    git \
    curl \
    gosu \
    libjpeg62-turbo \
    libpq5 \
    libwebp7 \
    xmlsec1 \
    libjemalloc2 \
    && rm -rf /var/lib/apt/lists/*
ENV RUSTUP_HOME=/rust
ENV CARGO_HOME=/cargo
ENV PATH=/cargo/bin:/rust/bin:$PATH
RUN mkdir /rust /cargo
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path --default-toolchain stable --profile minimal


# Make a base copy of the editable source tree, so that we have something to
# install and build now — even though it's going to be covered up by a mount
# at runtime.
COPY synapse /editable-src/synapse/
COPY rust /editable-src/rust/
# ... and what we need to `pip install`.
COPY pyproject.toml poetry.lock README.rst build_rust.py Cargo.toml Cargo.lock /editable-src/

RUN pip install poetry
RUN poetry config virtualenvs.create false
RUN cd /editable-src && poetry install --extras all

# Make copies of useful things for inspection:
# - the Rust module (must be copied to the editable source tree before startup)
# - poetry.lock is useful for checking if dependencies have changed.
RUN cp /editable-src/synapse/synapse_rust.abi3.so /synapse_rust.abi3.so.bak
RUN cp /editable-src/poetry.lock /poetry.lock.bak


### Extra setup from original Dockerfile
COPY ./docker/start.py /start.py
COPY ./docker/conf /conf

EXPOSE 8008/tcp 8009/tcp 8448/tcp

ENTRYPOINT ["/start.py"]

HEALTHCHECK --start-period=5s --interval=15s --timeout=5s \
    CMD curl -fSs http://localhost:8008/health || exit 1
