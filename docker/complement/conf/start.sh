#!/bin/sh

set -e

sed -i "s/SERVER_NAME/${SERVER_NAME}/g" /conf/homeserver.yaml

# Add the application service registration files to the homeserver.yaml config
for filename in /complement/appservice/*.yaml; do
  [ -f "$filename" ] || break

  as_id=$(basename "$filename" .yaml)

  # Insert the path to the registration file and the AS_REGISTRATION_FILES marker after 
  # so we can add the next application service in the next iteration of this for loop
  sed -i "s/AS_REGISTRATION_FILES/  - \/complement\/appservice\/${as_id}.yaml\nAS_REGISTRATION_FILES/g" /conf/homeserver.yaml
done
# Remove the AS_REGISTRATION_FILES entry
sed -i "s/AS_REGISTRATION_FILES//g" /conf/homeserver.yaml

# generate an ssl key and cert for the server, signed by the complement CA
openssl genrsa -out /conf/server.tls.key 2048

openssl req -new -key /conf/server.tls.key -out /conf/server.tls.csr \
  -subj "/CN=${SERVER_NAME}"
openssl x509 -req -in /conf/server.tls.csr \
  -CA /complement/ca/ca.crt -CAkey /complement/ca/ca.key -set_serial 1 \
  -out /conf/server.tls.crt

exec python -m synapse.app.homeserver -c /conf/homeserver.yaml "$@"

