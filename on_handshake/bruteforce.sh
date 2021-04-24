#!/bin/bash

echo 'bruteforcing WPA'

screen -dmS aircrack aircrack-ng -w on_handshake/rockyou.txt "$1" -l "handshakes/$2.txt"
