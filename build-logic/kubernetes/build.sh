#!/bin/bash

docker build -f ../docker/Dockerfile -t localhost:32000/kaxis-jdk17-slim:latest
docker push localhost:32000/kaxis-jdk17-slim:latest

