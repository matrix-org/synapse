#! /usr/bin/env bash
docker build . -f Dockerfile-pgtests -t synapsepgtests
docker run --rm -it -v $(pwd)\:/src synapsepgtests
