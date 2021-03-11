#!/bin/bash

WAIT=1
TIMEOUT=10
DPORT=3389
HOME='/home/pi'
export DISPLAY=:1
time=$(date +'%H:%M:%S_%d.%m.%Y')

if nc -nw $WAIT $1 $DPORT < /dev/null 2> /dev/null; then
	echo 'screenshoting RDP'
	echo yes | timeout $TIMEOUT rdesktop -u '' "$1" > /dev/null 2> /dev/null &
	sleep 5
	window_id=$(xwininfo -root -tree | grep '("rdesktop" "rdesktop")' | awk '{print $1}')
	if [ x$window_id != "x" ]; then
		import -window $window_id "$HOME/rdp_$time.png"
		echo "[+] $HOME/rdp_$time.png"
		xkill -id $window_id
	fi
fi
