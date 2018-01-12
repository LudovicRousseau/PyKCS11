#!/bin/sh

set -e

# (re)create a PKCS#11 token using SoftHSM v2

rm -r /var/lib/softhsm/tokens/*
softhsm2-util --init-token --label "A token" --pin 1234 --so-pin 123456 --slot 0
