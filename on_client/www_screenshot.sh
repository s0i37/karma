#!/bin/bash

WAIT=2
TIMEOUT=60
HTTP_PORTS=(80 8080)
HTTPS_PORTS=(443 8443)
export DISPLAY=:0
time=$(date +'%H:%M:%S_%d.%m.%Y')

function www_screenshot(){
	timeout $TIMEOUT surf -t "$1" > /dev/null 2> /dev/null &
	sleep $[TIMEOUT-2]
	window_id=$(xwininfo -root -tree | grep '.*|.*("surf" "Surf")' | awk '{print $1}')
	if [ x$window_id != "x" ]; then
		import -window $window_id "www-${2}_${3}_${time}.png"
		echo "[+] www-${2}_${3}_${time}.png"
		xkill -id $window_id > /dev/null 2>&1
	fi
}

for port in ${HTTP_PORTS[*]}
do
	if nc -nw $WAIT $1 $port < /dev/null 2> /dev/null; then
		echo "[*] screenshoting http://$1:$port"
		www_screenshot "http://$1:$port" $1 $port
	fi
done

for port in ${HTTPS_PORTS[*]}
do
	if nc -nw $WAIT $1 $port < /dev/null 2> /dev/null; then
		echo "[*] screenshoting https://$1:$port"
		www_screenshot "https://$1:$port" $1 $port
	fi
done
