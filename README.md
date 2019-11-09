# TCPioneer
TCPioneer is a program for Windows that protects the TCP connections from being interfered.

## Run as Client
run tcpioneer.exe to start the program
## Run as Service
run install.bat to install the service

## How to configure
server=IP:Port #domain in config will use this DNS(DNSoverTCP)  
ttl=*          #if ttl is not zero, the fake tcp packet will use this TTL  
md5=true/false #the fake tcp packets will have md5 option  
csum=true/false #the fake tcp packets will have a wrong checksum
tcpfastopen=true/false #SYN packet will take a part of data when the server supports TCP Fast Open  
domain=ip      #this domain will use this IP, if Domain only the IP will be resolved by DNSoverTCP  

## How to get the TTL
tracert 8.8.8.8
