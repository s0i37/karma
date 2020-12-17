#!/bin/bash

WAIT_SEC=1
DPORT=3389
exit

nc -w $WAIT_SEC $1 $DPORT 2> /dev/null && {
	echo 'screenshoting RDP'

	timeout -s KILL 8 rdpy-rdpscreenshot.py -w 1280 -l 800 -o ./ $1 2> /dev/null
}

