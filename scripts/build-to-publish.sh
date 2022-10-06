#!/bin/sh

set -euf

# Use Podman if installed, else use Docker
if hash podman 2> /dev/null
then
  DOCKER_COMMAND=podman
else
  DOCKER_COMMAND=docker
fi

mkdir -p ./dist
chmod 0777 ./dist

$DOCKER_COMMAND build -t aleph-client -f docker/Dockerfile .
$DOCKER_COMMAND run -ti --rm \
  -w /opt/aleph-client \
  -v "$(pwd)/dist":/opt/aleph-client/dist \
  --entrypoint /bin/bash \
  aleph-client
