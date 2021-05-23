#!/bin/bash
#
# Author: Pierre Dahmani
# Created: 23.05.2021
#
# Description: test script to start synapse. requires gen-conf.sh to be ran
# before.

docker run -d --name synapse \
    --mount type=volume,src=synapse-data,dst=/data \
    -p 8008:8008 \
    matrixdotorg/synapse:latest

# tail log of latest container to see if we were successfull
docker container logs -f "$(docker ps -ql)"
