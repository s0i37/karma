#!/bin/bash

WAIT=2
DPORT=554

if nc -nw $WAIT -c $1 $DPORT < /dev/null 2> /dev/null; then
	echo '[*] RTSP streaming'
	#nmap -Pn -n -p 554 --script rtsp-methods $1
	nmap -Pn -n -p 554 --script rtsp-url-brute $1 -oX /tmp/rtsp.xml > /dev/null 2>&1
	url=$(cat /tmp/rtsp.xml | xmllint --xpath '//table[@key="discovered"]/elem/text()' - 2>/dev/null | head -n 1)
	if [ -n "$url" ]; then
		echo "[*] $url"
		#timeout 2 cvlc "$url" --sout=file/ts:/tmp/"$1.mpg" #> /dev/null 2>&1
		ffmpeg -i "$url" -vframes 1 -y "/tmp/$1.jpg" > /dev/null
	fi
	if [ -s "/tmp/$1.jpg" ]; then
		cp "/tmp/$1.jpg" "$1.jpg"
		echo "[+] $(ls -lh $1.jpg)"
	fi
fi
