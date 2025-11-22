#!/bin/sh
set -euf

rm -f /tmp/v.sock
rm -f /tmp/firecracker.socket
./bin/firecracker --api-sock /tmp/firecracker.socket --config-file ./utils/vm_config_base.json
rm -f /tmp/v.sock
rm -f /tmp/firecracker.socket
