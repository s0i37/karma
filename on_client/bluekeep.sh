#!/bin/bash

WAIT=2
DPORT=3389
HOME='/home/pi'
#https://github.com/HynekPetrak/detect_bluekeep.py/blob/master/detect_bluekeep.py

if nc -nw $WAIT $1 $DPORT < /dev/null 2> /dev/null; then
	echo '[*] checking BlueKeep'
	$HOME/src/bluekeep_check.py $1 > /tmp/bluekeep.log 2>&1
	if grep 'VULNERABLE' /tmp/bluekeep.log --color=auto; then
		led red on 2> /dev/null
	fi
fi