#!/bin/bash

echo 'writing trafic'

tcpdump -i "$1" -nn -w "$2_$RANDOM.pcap"
