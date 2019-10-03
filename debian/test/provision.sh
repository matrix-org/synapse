#!/bin/bash
#
# provisioning script for vagrant boxes for testing the matrix-synapse debs.
#
# Will install the most recent matrix-synapse-py3 deb for this platform from
# the /debs directory.

set -e

apt-get update
apt-get install -y lsb-release

deb=`ls /debs/matrix-synapse-py3_*+$(lsb_release -cs)*.deb | sort | tail -n1`

debconf-set-selections <<EOF
matrix-synapse matrix-synapse/report-stats boolean false
matrix-synapse matrix-synapse/server-name string localhost:18448
EOF

dpkg -i "$deb"

sed -i -e '/port: 8...$/{s/8448/18448/; s/8008/18008/}' -e '$aregistration_shared_secret: secret' /etc/matrix-synapse/homeserver.yaml
systemctl restart matrix-synapse
