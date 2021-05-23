#!/bin/bash
#
# Author: Pierre Dahmani
# Created: 23.05.2021
#
# Description: tests generation of config files for matrix.

DEFAULT_VOLUME_PATH=/var/lib/docker/volumes/synapse-data/_data/my.matrix.host.log.config
check_filename_correct(){
# checks if the filename was set to /data/homeserver.log.
if $(grep -q "filename: /data/homeserver.log" $DEFAULT_VOLUME_PATH); then
    echo "success."
    echo "Filename is now set to /data/homeserver.log"
else
    echo "failure."
    echo "Filename is NOT set to /data/homeserver.log"
fi
}
# builds the docker image with the files that are given in this repo / merge
# request.
# (expects you to start this from the directory the script is located at)
cd ../.. || (echo "../../ did not exist?" && exit 1)
docker build -f docker/Dockerfile  -t pierrefha:matrix-test .

# removes the default docker volume from the example
docker volume rm synapse-data

echo -e "generating config with the current public matrix image...\n"
# generates configuration files
docker run -it --rm \
    --mount type=volume,src=synapse-data,dst=/data \
    -e SYNAPSE_SERVER_NAME=my.matrix.host \
    -e SYNAPSE_REPORT_STATS=yes \
    matrixdotorg/synapse:latest generate

echo -e "\nrunning test..."
check_filename_correct

# removes the just created volume. try again with the fixed version.
echo "removing the volume we just created..."
docker volume rm synapse-data

echo -e "generating config with the changes.\n"
# generates configuration files with the image we just built
docker run -it --rm \
    --mount type=volume,src=synapse-data,dst=/data \
    -e SYNAPSE_SERVER_NAME=my.matrix.host \
    -e SYNAPSE_REPORT_STATS=yes \
    pierrefha:matrix-test generate

echo -e "\nrunning test..."
check_filename_correct
