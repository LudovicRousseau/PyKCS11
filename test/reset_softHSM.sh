#!/bin/bash

set -e

# Remove any existing tokens
declare -a softHSM_paths=(
	/var/lib/softhsm/tokens
	/usr/local/var/lib/softhsm/tokens
	/opt/homebrew/var/lib/softhsm/tokens
)
for p in "${softHSM_paths[@]}"
do
	if [ -d "$p" ]
	then
		echo "Found tokens in $p"
		for d in "$p"/*
		do
			echo "Erase $d"
			rm -rf "$d"
		done
	fi
done

# (re)create a PKCS#11 token using SoftHSM v2
softhsm2-util --init-token --label "A token" --pin 1234 --so-pin 123456 --slot 0
softhsm2-util --show-slots
