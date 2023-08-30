#/bin/bash
# Run Docker in WSL2 https://nickjanetakis.com/blog/install-docker-in-wsl-2-without-docker-desktop
# We need to create an azure token in a non-standard directory which is then mapped into the container 
# export AZURE_CONFIG_DIR=$HOME/.azure_docker
# az login
# e.g. ./build_and_deploy.sh main TlsCertificateManagement
rg="$1"
fn="$2"
[[ -z "$fn" ]] && { echo "Error: build_and_deploy <RESOURCE_GROUP> <FUNCTION_NAME>"; exit 1; }
mkdir -p $HOME/.azure_docker
set AZURE_CONFIG_DIR=$HOME/.azure_docker
docker build . -t functions_builder
docker run -e RESOURCE_GROUP=$rg -e FUNCTION_NAME=$fn --rm --mount type=bind,source=$HOME/.azure_docker,target=/root/.azure --mount type=bind,source=$PWD,target=/src functions_builder
  