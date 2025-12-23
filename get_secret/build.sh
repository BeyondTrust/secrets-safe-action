#!/bin/bash
set -e
set -x

echo "Building secret creation action...."
python -m build /home/felipe/integratios/btfhernandez/ps-integration-library/

echo "Moving Artifact...."
cp /home/felipe/integratios/btfhernandez/ps-integration-library/dist/beyondtrust_bips_library-2.0-py3-none-any.whl \
   /home/felipe/integratios/btfhernandez/secrets-safe-action/get_secret/dist

docker compose build
docker compose up