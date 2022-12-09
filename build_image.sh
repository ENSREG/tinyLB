# !/bin/bash
docker build . -t ianchen0119/lb
docker image ls | grep none | awk '{print $3}' | xargs docker image rm
# docker run --rm -it --privileged ianchen0119/lb:latest bash