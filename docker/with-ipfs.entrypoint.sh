#!/bin/bash

set -euo pipefail

# Initialize IPFS if it has not been done yet
if [ ! -f /var/lib/ipfs/config ]; then
  chown -R aleph:aleph /var/lib/ipfs
  su aleph -c "/opt/go-ipfs/ipfs init --profile server"
fi

# Start IPFS as a daemon
su aleph -c "/opt/go-ipfs/ipfs daemon --enable-pubsub-experiment" &

# Run a shell
su aleph -c "/bin/bash"
