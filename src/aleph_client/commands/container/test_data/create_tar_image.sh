#!/bin/sh

docker build -t test-image .
docker save test-image > test-image.tar || rm test-image.tar
