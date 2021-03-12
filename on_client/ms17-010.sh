#!/bin/bash

WAIT=1
DPORT=445
HOME='/home/pi'

if nc -nw $WAIT $1 $DPORT < /dev/null 2> /dev/null; then
	echo '[*] checking MS17-010'
	python2 $HOME/src/MS17-010/checker.py $1 > /tmp/ms17-010.log
	if grep -q 'The target is not patched' /tmp/ms17-010.log; then
		led red on 2> /dev/null
	fi
	cat /tmp/ms17-010.log
fi