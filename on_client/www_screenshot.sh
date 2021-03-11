#!/bin/bash

WAIT=1
TIMEOUT=10
HTTP_PORTS=(80 8080)
HTTPS_PORTS=(443 8443)
HOME='/home/pi/'
export DISPLAY=:1
time=$(date +'%H:%M:%S_%d.%m.%Y')

function www_screenshot(){
	timeout $TIMEOUT surf "$1" > /dev/null 2> /dev/null &
	sleep 5
	window_id=$(xwininfo -root -tree | grep '.*|.*("surf" "Surf")' | awk '{print $1}')
	if [ x$window_id != "x" ]; then
		import -window $window_id "$HOME/www_${time}_${2}.png"
		echo "[+] $HOME/www_${time}_${2}.png"
		xkill -id $window_id
	fi
}

for port in ${HTTP_PORTS[*]}
do
	if nc -nw $WAIT $1 $port < /dev/null 2> /dev/null; then
		echo "screenshoting http://$1:$port"
		www_screenshot "http://$1:$port" $port
	fi
done

for port in ${HTTPS_PORTS[*]}
do
	if nc -nw $WAIT $1 $port < /dev/null 2> /dev/null; then
		echo "screenshoting https://$1:$port"
		www_screenshot "https://$1:$port" $port
	fi
done
