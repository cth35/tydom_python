#!/bin/sh

# Make docker image
docker build --tag=tydom2mqtt --file=.Dockerfile .
