#!/bin/bash

WAIT=2
PORTS=(80 8080 443)

for port in ${PORTS[*]}
do
	if nc -nw $WAIT $1 $port < /dev/null 2> /dev/null; then
		echo '[*] running Routersploit attacks'
		rsf.py -m 'scanners/cameras/camera_scan' -s "target $1" 2> /dev/null
		break
	fi
done
