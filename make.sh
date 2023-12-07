#!/bin/bash

cargo vendor 1> ./cargo_config
if [ ! -f "SUSE_CA_Root.pem" ]; then
    echo "Couldn't find the SUSE Root CA, touching it"
    touch SUSE_CA_Root.pem
fi
docker buildx build --pull --push --platform "linux/amd64" \
    -f ./Dockerfile \
    -t firstyear/ldap-proxy:latest \
    .
