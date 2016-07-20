#!/bin/bash

#
#  ncat client  (server listening on 2121-2122 port)
#
iptables -v -A OUTPUT     -t mangle -j NFQUEUE --queue-num 0 --queue-bypass -p TCP --dport 2121:2122
iptables -v -A PREROUTING -t mangle -j NFQUEUE --queue-num 0 --queue-bypass -p TCP --sport 2121:2122

#
#  ncat server listening on 2121-2122 port
#
iptables -v -A OUTPUT     -t mangle -j NFQUEUE --queue-num 0 --queue-bypass -p TCP --sport 2121:2122
iptables -v -A PREROUTING -t mangle -j NFQUEUE --queue-num 0 --queue-bypass -p TCP --dport 2121:2122

# 
# WEB CLIENT: process traffic from  a local web client connecting to a remote server in port 80
#
iptables -v -A OUTPUT     -t mangle -j NFQUEUE --queue-num 0 --queue-bypass -p TCP --dport 80
iptables -v -A PREROUTING -t mangle -j NFQUEUE --queue-num 0 --queue-bypass -p TCP --sport 80

#
# WEB SERVER: process traffic to a local web server running on port 80
#
iptables -v -A PREROUTING -t mangle -j NFQUEUE --queue-num 0 --queue-bypass -p TCP --dport 80
iptables -v -A OUTPUT     -t mangle -j NFQUEUE --queue-num 0 --queue-bypass -p TCP --sport 80

#
# FTP CLIENT: control traffic
#
iptables -v -A OUTPUT     -t mangle -j NFQUEUE --queue-num 0 --queue-bypass -p TCP --dport 21
iptables -v -A PREROUTING -t mangle -j NFQUEUE --queue-num 0 --queue-bypass -p TCP --sport 21

#
# FTP SERVER: control traffic
#
iptables -v -A OUTPUT     -t mangle -j NFQUEUE --queue-num 0 --queue-bypass -p TCP --sport 21
iptables -v -A PREROUTING -t mangle -j NFQUEUE --queue-num 0 --queue-bypass -p TCP --dport 21

#
# FTP: data traffic
#
iptables -v -A OUTPUT     -t mangle -j NFQUEUE --queue-num 0 --queue-bypass -p TCP --sport 9000:9499
iptables -v -A OUTPUT     -t mangle -j NFQUEUE --queue-num 0 --queue-bypass -p TCP --dport 9000:9499
iptables -v -A PREROUTING -t mangle -j NFQUEUE --queue-num 0 --queue-bypass -p TCP --sport 9000:9499
iptables -v -A PREROUTING -t mangle -j NFQUEUE --queue-num 0 --queue-bypass -p TCP --dport 9000:9499
