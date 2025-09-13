#!/bin/bash

echo "Building StrongDM Resource Manager OCI Container..."

# Build container image
docker build -t strongdm-manager:latest .

# Create container without starting it
docker create --name strongdm-manager-export strongdm-manager:latest

# Export container to tar file
docker export strongdm-manager-export > strongdm-manager.tar

# Cleanup
docker rm strongdm-manager-export

echo "Container built and exported to strongdm-manager.tar"
echo "To run: docker load < strongdm-manager.tar && docker run -it --rm -e DISPLAY=\$DISPLAY -v /tmp/.X11-unix:/tmp/.X11-unix strongdm-manager:latest"
