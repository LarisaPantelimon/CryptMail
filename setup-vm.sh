#!/bin/bash
sudo apt-get update && sudo apt-get upgrade -y

# Install Docker
 sudo apt-get install -y docker.io
 sudo systemctl start docker
 sudo systemctl enable docker
 sudo usermod -aG docker $USER
#
## # Install Docker Compose
 sudo curl -L "https://github.com/docker/compose/releases/download/v2.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
#
# # Install git and other utilities
 sudo apt-get install -y git
#
 # Verify installations
 docker --version
 docker-compose --version

 echo "Docker and Docker Compose installed. Please log out and log back in to apply docker group changes."
