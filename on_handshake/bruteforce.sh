#!/bin/bash

echo 'bruteforcing WPA'
HOME='/home/pi'

screen -dmS aircrack aircrack-ng -w /usr/share/wordlists/rockyou.txt "$1" -l "$HOME/karma/handshakes/$2.txt"
