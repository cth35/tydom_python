
#!/bin/sh

# We could see the env-file syntax [here](https://docs.docker.com/compose/env-file)

# Execute docker with .env file
docker build --tag=tydom2mqtt/dev --file=dev.Dockerfile .
docker run --rm -it --network="host" --env-file=.env -v $(pwd):/opt/app/ tydom2mqtt/dev
