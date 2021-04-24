#!/bin/bash

WAIT=2
TIMEOUT=30
DPORT=3389
export DISPLAY=:0
time=$(date +'%H:%M:%S_%d.%m.%Y')

if nc -nw $WAIT $1 $DPORT < /dev/null 2> /dev/null; then
	echo '[*] screenshoting RDP'
	echo yes | timeout $TIMEOUT rdesktop -u '' "$1" > /dev/null 2> /dev/null &
	sleep $[TIMEOUT-2]
	window_id=$(xwininfo -root -tree | grep '("rdesktop" "rdesktop")' | awk '{print $1}')
	if [ x$window_id != "x" ]; then
		import -window $window_id "rdp-${1}_${time}.png"
		echo "[+] rdp-${1}_${time}.png"
		xkill -id $window_id > /dev/null 2>&1
	fi
fi
