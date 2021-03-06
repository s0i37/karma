#!/bin/bash

WAIT=1
HTTP_PORTS=(80 8080)
HTTPS_PORTS=(443 8443)
HOME='/home/pi/'

for port in ${HTTP_PORTS[*]}
do
	if nc -nw $WAIT $1 $port < /dev/null 2> /dev/null; then
		echo "screenshoting $port"
		$HOME/src/crawl/linux/wwwscreen.js --url "http://$1:$port"
	fi
done

for port in ${HTTPS_PORTS[*]}
do
	if nc -nw $WAIT $1 $port < /dev/null 2> /dev/null; then
		echo "screenshoting $port"
		$HOME/src/crawl/linux/wwwscreen.js --url "https://$1:$port"
	fi
done
