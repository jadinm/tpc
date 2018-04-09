#!/bin/bash

sudo tc qdisc add dev lo root handle 4: red limit 1000kB avpkt 100 probability 0.1 min 500 max 2kB ecn
sudo iptables -A INPUT -m ecn --ecn-ip-ect 3 -j NFQUEUE --queue-num 0 # -j LOG --log-prefix='[netfilter] ' 
sudo ip6tables -A INPUT -m ecn --ecn-ip-ect 3 -j NFQUEUE --queue-num 0 # -j LOG --log-prefix='[netfilter] '

