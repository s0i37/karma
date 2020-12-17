#!/bin/bash

WAIT_SEC=1
HTTP_PORTS=(80 8080)
HTTPS_PORTS=(443 8443)

for port in ${HTTP_PORTS[*]}
do
	nc -w $WAIT_SEC $1 $port 2> /dev/null && {
		echo "screenshoting $port"

		/home/soier/src/simple_crawl/wwwscreen.js "http://$1:$port"
	}
done

for port in ${HTTPS_PORTS[*]}
do
	nc -w $WAIT_SEC $1 $port 2> /dev/null && {
		echo "screenshoting $port"

		/home/soier/src/simple_crawl/wwwscreen.js "https://$1:$port"
	}
done
