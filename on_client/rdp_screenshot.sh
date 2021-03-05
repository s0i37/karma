#!/bin/bash

WAIT=1
TIMEOUT=10
DPORT=3389
HOME='/home/pi'
time=$(date +'%H:%M:%S_%d.%m.%Y')

if nc -nw $WAIT $1 $DPORT < /dev/null 2> /dev/null; then
	echo 'screenshoting RDP'
	#timeout -s KILL 8 rdpy-rdpscreenshot.py -w 1280 -l 800 -o ./ $1 2> /dev/null
	echo yes | timeout $TIMEOUT rdesktop -u '' $1 > /dev/null 2> /dev/null &
	sleep 5
	xwininfo -root -tree|grep '("rdesktop" "rdesktop")'|read windows_id _
	import -window $windows_id "$HOME/rdp_$time.png"
fi
