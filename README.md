# TCPioneer
TCPioneer is a program for Windows that protects the TCP connections from being interfered.

## Run as Client
run tcpioneer.exe to start the program
## Run as Service
run install.bat to install the service

## How to configure
  server=IP:Port         `domain in config will use this DNS(DNSoverTCP),if not set it will use the DNS of system`  
  ipv6=true/false        `Domain below will enable/disable IPv6`  
  ttl=*                  `if ttl is not zero, the fake tcp packet will use this TTL`  
  domain=ip,ip,...       `this domain will use these IPs`  
  domain                 `this domain will be resolved by DNS`  
  method=*               `the methods to modify TCP`
### methods:
  w-md5                  `the fake tcp packets will have a wrong md5 option`  
  w-csum                 `the fake tcp packets will have a wrong checksum`  
  w-ack                  `the fake tcp packets will have a wrong ACK number`  
  tfo                    `SYN packet will take a part of data when the server supports TCP Fast Open`  
  https                  `the domain below will be move to https when using http on port 80`  

## How to get the TTL
tracert 8.8.8.8  
set the ttl to the TTL of the node whose latency suddenly increased.
