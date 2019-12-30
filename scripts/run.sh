#!/bin/sh

# We could see the env-file syntax [here](https://docs.docker.com/compose/env-file)

# Execute docker with .env file
docker run --rm -it -u 0 --network="host" --env-file=.env tydom2mqtt python main.py "$@"

