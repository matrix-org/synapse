# A dockerfile which builds an image suitable for testing Synapse under
# complement.

ARG SYNAPSE_VERSION=latest

FROM matrixdotorg/synapse:${SYNAPSE_VERSION}

ENV SERVER_NAME=localhost

COPY conf/* /conf/

# generate a signing key
RUN generate_signing_key -o /conf/server.signing.key

WORKDIR /data

EXPOSE 8008 8448

ENTRYPOINT ["/conf/start.sh"]

HEALTHCHECK --start-period=5s --interval=1s --timeout=1s \
    CMD curl -fSs http://localhost:8008/health || exit 1
