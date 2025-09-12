#!/bin/sh

set -e

# (re)create a PKCS#11 token using SoftHSM v2

[ -d  /var/lib/softhsm/tokens/ ] && rm -rf /var/lib/softhsm/tokens/*
[ -d /usr/local/var/lib/softhsm/tokens ] && rm -rf /usr/local/var/lib/softhsm/tokens/*
[ -d /opt/homebrew/var/lib/softhsm/tokens ] && rm -rf /opt/homebrew/var/lib/softhsm/tokens/*

softhsm2-util --init-token --label "A token" --pin 1234 --so-pin 123456 --slot 0
softhsm2-util --show-slots
