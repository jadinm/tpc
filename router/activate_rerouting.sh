#!/bin/bash

sudo sysctl net.ipv6.conf.all.seg6_enabled=1
sudo sysctl net.ipv6.conf.lo.seg6_enabled=1
sudo tc qdisc add dev lo root handle 4: red limit 1000kB avpkt 100 probability 0.1 min 500 max 2kB ecn
sudo ip6tables -A INPUT -m ecn --ecn-ip-ect 3 -p tcp -j NFQUEUE --queue-num 0 # -j LOG --log-prefix='[netfilter] '
sudo ip6tables -A INPUT -m ecn --ecn-ip-ect 3 -p udp -j NFQUEUE --queue-num 0 # -j LOG --log-prefix='[netfilter] '

