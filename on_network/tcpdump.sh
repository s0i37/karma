#!/bin/bash

echo '[*] writing trafic'
time=$(date +'%H:%M:%S_%d.%m.%Y')

tcpdump -i "$1" -nn -w "${2}_${time}_${RANDOM}.pcap"
