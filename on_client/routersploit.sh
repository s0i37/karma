#!/bin/bash

WAIT=2
DPORT=80
HOME='/home/pi'

if nc -nw $WAIT $1 $DPORT < /dev/null 2> /dev/null; then
	echo '[*] running Routersploit attacks'
	$HOME/src/routersploit/rsf.py -m 'scanners/cameras/camera_scan' -s "target $1"
fi
