# TCPioneer
TCPioneer is a program for Windows that protects the TCP connections from being interfered.

## Run as Client
run tcpioneer.exe to start the program
## Run as Service
run install.bat to install the service

## How to configure
server=IP:Port #domain in config will use this DNS(DNSoverTCP).
ttl=*          #if ttl is not zero, the fake tcp packet will use this TTL.
md5=true/false #the fake tcp packet will have md5 option.
domain=ip      #this domain will use this IP, if Domain only the IP will be resolved by DNSoverTCP.

## How to get the TTL
tracert 8.8.8.8
