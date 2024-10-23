#!/bin/bash

echo '[*] HTTP cleartext monitoring'

ngrep -d "$1" -i 'cookie|passw|token' 'port 80 or port 8080' 2>&1 > http.log &

tail -n 0 -f http.log | while read line
do
	echo "$line" | grep -v '^match:' | grep -ai -e cookie -e passw -e token --color=auto && led yellow on 2> /dev/null
done
