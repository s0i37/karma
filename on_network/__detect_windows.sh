#!/bin/bash

if tcpdump -i "$1" -nn -c 1 'ip[8]==128' 2>&1|grep -q 'IP'; then
	echo "WINDOWS detected"
	echo "WINDOWS detected"
	echo "WINDOWS detected"
	echo "WINDOWS detected"
	echo "WINDOWS detected"
	echo "WINDOWS detected"
	echo "WINDOWS detected"
	echo "WINDOWS detected"
	echo "WINDOWS detected"
	echo "WINDOWS detected"
fi
