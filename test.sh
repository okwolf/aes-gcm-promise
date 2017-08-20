#!/bin/bash
docker build -t aes-gcm-promise .
docker run --rm -ti aes-gcm-promise "$@"
