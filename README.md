docker build -t benchmark-image --build-arg HTTP_PROXY=$http_proxy --build-arg HTTPS_PROXY=$http_proxy -f .devcontainer/Dockerfile . 
