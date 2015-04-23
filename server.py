#!/usr/bin/python           # This is server.py file

import socket               # Import socket module
import struct
import sys
import binascii
from uuid import getnode as get_mac
from random import randint
dict = {};

def buildPacket(req, data):
	msg = ''.join("{:02x}".format(ord(c)) for c in data)
	packet = b''
	packet += b'\x02'   #OP
	packet += b'\x01'   #HTYPE
	packet += b'\x06'   #HLEN
	packet += b'\x00'   #HOPS
	packet += struct.pack("4B",int(msg[8:10],16),int(msg[10:12],16),int(msg[12:14],16),int(msg[14:16],16))    #XID
	packet += b'\x00\x00'    #SECS
	packet += b'\x00\x00'   #FLAGS
	packet += struct.pack("4B",int(msg[16:18],16),int(msg[18:20],16),int(msg[20:22],16),int(msg[22:24],16))   #Client IP address: 0.0.0.0
	if(req != 0):
		packet += struct.pack("4B",int(msg[req:(req+2)],16),int(msg[(req+2):(req+4)],16),int(msg[(req+4):(req+6)],16),int(msg[(req+6):(req+8)],16))   #Your IP address
	else:
		packet += struct.pack("4B",192,168,1,randint(0, 255))
	packet += b'\x00\x00\x00\x00'   #Server IP address: 0.0.0.0
	packet += b'\x00\x00\x00\x00'   #Gateway IP address: 0.0.0.0
	packet += struct.pack("8B",int(msg[56:58],16),int(msg[58:60],16),int(msg[60:62],16),int(msg[62:64],16),int(msg[64:66],16),int(msg[66:68],16),int(msg[68:70],16),int(msg[70:72],16))   #Client MAC address: 00:05:3c:04:8d:59
	packet += b'\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
	#packet += b'\x00' * 67  #Server host name not given
	packet += b'\x00' * 192 #Boot file
	packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
	if(int(msg[484:486],16) == 1):
		packet += b'\x35\x01\x02'   #Option: (t=53,l=1) DHCP Message Type = DHCP Offer
	elif(int(msg[484:486],16) == 3):
		packet += b'\x35\x01\x05'   #Option: (t=53,l=1) DHCP Message Type = DHCP ACK
	packet += b'\x01\x04\xff\xff\xff\x00'   #Option: (t=1,l=4) DHCP Message Type = Subnet Mask
	packet += b'\x03\x04\xc0\xa8\x01\x01'   #Option: (t=3,l=4) DHCP Message Type = Router
	#packet += b'\x33\x04\xff\xff\xff\x00'   #Option: (t=51,l=4) DHCP Message Type = Address Time
	packet += b'\x36\x04\xc0\xa8\x01\x01'   #Option: (t=54,l=4) DHCP Message Type = DHCP Server Id
	packet += b'\xff'   #End Option
	return packet


def printSock(data):
	msg = ''.join("{:02x}".format(ord(c)) for c in data)
	print ('OP: 0x' + str(msg[0:2]))
	print ('transactionID(XID): 0x' + str(msg[8:16]))
	print ('CIADDR (Client IP Address): ' + str(int(msg[24:26],16)) + '.' + str(int(msg[26:28],16)) + '.' + str(int(msg[28:30],16)) + '.' + str(int(msg[30:32],16)))
	print ('YIADDR (Your IP Address): ' + str(int(msg[32:34],16)) + '.' + str(int(msg[34:36],16)) + '.' + str(int(msg[36:38],16)) + '.' + str(int(msg[38:40],16)))
	print ('CHADDR (Client MAC address): ' + str(msg[56:58]) + '-' + str(msg[58:60]) + '-' + str(msg[60:62]) + '-' + str(msg[62:64])+ '-' + str(msg[64:66])+ '-' + str(msg[66:68])+ '-' + str(msg[68:70])+ '-' + str(msg[70:72]))
	print ('Magic Cookie: 0x' + str(msg[472:480]))
	print ('DHCP Options ' + str(int(msg[480:482],16)) + ': '),
	if(int(msg[484:486],16) == 1):
		print('DHCP Discover')
	elif(int(msg[484:486],16) == 3):
		print('DHCP Request')
	j = 486
	iprequest = 0
	while int(msg[j:(j+2)],16) != 255:
		print ('DHCP Options ' + str(int(msg[j:(j+2)],16)) + ': '),
		i = 0
		if(int(msg[j:(j+2)],16) == 50):
			iprequest = j+4
		while i< int(msg[(j+2):(j+4)],16):
			if(i != 0):
				print('.'),
			print (int(msg[(j+4+i*2):(j+6+i*2)],16)),
			i+=1
		print ('')
		j = j + 2*2 + (int(msg[(j+2):(j+4)],16))*2
	return iprequest

if __name__ == '__main__':
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)         # Create a socket object
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) #broadcast
	#host = socket.gethostname() # Get local machine name
	#port = 12345                # Reserve a port for your service.

	print ('Server started!')

	try:
		sock.bind(('', 67))
	except Exception as e:
		print('port 67 in use...')
		sock.close()
		raw_input('press any key to quit...')
		sys.exit(0)

	while True:
		print ('Waiting for clients...')
		#msg = sock.recv(1024)
		data, addr = sock.recvfrom(2048)
		#msg = ''.join("{:02x}".format(ord(x)) for x in data)
		req = printSock(data)
		sock.sendto(buildPacket(req, data), ('<broadcast>', 68))
	
	sock.close()   #we close the socket

	print('end')
	sys.exit(0)
