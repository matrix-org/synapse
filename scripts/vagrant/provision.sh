#!/bin/bash
set -e
set -x
sudo apt-get -y install build-essential python2.7-dev libffi-dev \
  python-pip python-setuptools sqlite3 \
  libssl-dev python-virtualenv libjpeg-dev libxslt1-dev apache2

cd /var/www/html/
wget -O - "https://vector.im/packages/vector-v0.8.2.tar.gz" | sudo tar xvvzf -
sudo chown -R ubuntu.ubuntu vector*

cd /home/ubuntu
virtualenv -p python2.7 ~/synapse
source ~/synapse/bin/activate
pip install --upgrade setuptools
pip install https://github.com/matrix-org/synapse/tarball/master
cd ~/synapse
python -m synapse.app.homeserver \
  --server-name localhost \
  --config-path homeserver.yaml \
  --generate-config \
  --report-stats=no
chown -R ubuntu.ubuntu ~/synapse
su ubuntu -c "synctl start"
TMPF=`mktemp`
sed 's/enable_registration: False/enable_registration: True/' < homeserver.yaml > $TMPF
mv $TMPF homeserver.yaml
#su ubuntu -c "register_new_matrix_user -c homeserver.yaml https://localhost:8448"
