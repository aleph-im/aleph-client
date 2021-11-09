#!/bin/sh

set -euf

# Use Podman if installed, else use Docker
if hash podman 2> /dev/null
then
  DOCKER_COMMAND=podman
else
  DOCKER_COMMAND=docker
fi

$DOCKER_COMMAND build -t aleph-client -f docker/Dockerfile .
$DOCKER_COMMAND run -ti --rm aleph-client pytest /opt/aleph-client/ "$@"
$DOCKER_COMMAND run -ti --rm aleph-client mypy /opt/aleph-client/src/ --ignore-missing-imports
