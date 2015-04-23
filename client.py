#!/usr/bin/python           # This is client.py file

import socket               # Import socket module
import struct
import sys
from uuid import getnode as get_mac
from random import randint

class DHCPDiscover:
	def __init__(self):
		self.transactionID = b''
		self.MACaddress = b''
		for i in range(4):
			t = randint(0, 255)
			self.transactionID += struct.pack('!B', t) 
		for i in range(8):
			t = randint(0, 255)
			self.MACaddress += struct.pack('!B', t)

	def buildPacket(self):
		packet = b''
		packet += b'\x01'   #OP
		packet += b'\x01'   #HTYPE
		packet += b'\x06'   #HLEN
		packet += b'\x00'   #HOPS
		packet += self.transactionID       #XID
		packet += b'\x00\x00'    #SECS
		packet += b'\x00\x00'   #FLAGS
		packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
		packet += b'\x00\x00\x00\x00'   #Your IP address: 0.0.0.0
		packet += b'\x00\x00\x00\x00'   #Server IP address: 0.0.0.0
		packet += b'\x00\x00\x00\x00'   #Gateway IP address: 0.0.0.0
		packet += self.MACaddress   #Client MAC address
		packet += b'\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
		packet += b'\x00' * 192 #Boot file
		packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
		packet += b'\x35\x01\x01'   #Option: (t=53,l=1) DHCP Message Type = DHCP Discover
		packet += struct.pack("6B",50,4,192,168,1,randint(0, 255))   #Option: (t=50,l=4) Address Request
		packet += b'\xff'   #End Option
		#print (''.join("{:02x}".format(ord(c)) for c in packet))
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
	if(int(msg[484:486],16) == 2):
		print('DHCP OFFER')
	elif(int(msg[484:486],16) == 5):
		print('DHCP ACK')
	j = 486
	while int(msg[j:(j+2)],16) != 255:
		print ('DHCP Options ' + str(int(msg[j:(j+2)],16)) + ': '),
		i = 0
		while i< int(msg[(j+2):(j+4)],16):
			if(i != 0):
				print('.'),
			print (int(msg[(j+4+i*2):(j+6+i*2)],16)),
			i+=1
		print ('')
		j = j + 2*2 + (int(msg[(j+2):(j+4)],16))*2

def buildREQUESTPacket(data):
	msg = ''.join("{:02x}".format(ord(c)) for c in data)
	packet = b''
	packet += b'\x01'   #OP
	packet += b'\x01'   #HTYPE
	packet += b'\x06'   #HLEN
	packet += b'\x00'   #HOPS
	packet += struct.pack("4B",int(msg[8:10],16),int(msg[10:12],16),int(msg[12:14],16),int(msg[14:16],16))    #XID
	packet += b'\x00\x00'    #SECS
	packet += b'\x00\x00'   #FLAGS
	packet += struct.pack("4B",int(msg[16:18],16),int(msg[18:20],16),int(msg[20:22],16),int(msg[22:24],16))   #Client IP address: 0.0.0.0
	packet += b'\xc0\xa8\x01\x64'   #Your IP address: 192.168.1.1
	packet += b'\x00\x00\x00\x00'   #Server IP address: 0.0.0.0
	packet += b'\x00\x00\x00\x00'   #Gateway IP address: 0.0.0.0
	packet += struct.pack("8B",int(msg[56:58],16),int(msg[58:60],16),int(msg[60:62],16),int(msg[62:64],16),int(msg[64:66],16),int(msg[66:68],16),int(msg[68:70],16),int(msg[70:72],16))   #Client MAC address: 
	packet += b'\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
	#packet += b'\x00' * 67  #Server host name not given
	packet += b'\x00' * 192 #Boot file
	packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
	packet += b'\x35\x01\x03'   #Option: (t=53,l=1) DHCP Message Type = DHCP REQUEST
	packet += struct.pack("6B",50,4,int(msg[32:34],16),int(msg[34:36],16),int(msg[36:38],16),int(msg[38:40],16))   #Option: (t=50,l=4) Address Request
	#packet += b'\x37\x03\x03\x01\x06'   #Option: (t=55,l=3) Parameter Request List
	packet += b'\xff'   #End Option
	#print (''.join("{:02x}".format(ord(c)) for c in packet))
	return packet
	
if __name__ == '__main__':
	dhcp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)         # Create a socket object
	dhcp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) #broadcast
	#host = socket.gethostname() # Get local machine name
	#port = 12345                # Reserve a port for your service.

	print ('Connecting to server')
	try:
		dhcp.bind(('', 68))    #we want to send from port 68
	except Exception as e:
		print('port 68 in use...')
		dhcp.close()
		raw_input('press any key to quit...')
		sys.exit(0)

	#buiding and sending the DHCPDiscover packet
	discoverPacket = DHCPDiscover()
	dhcp.sendto(discoverPacket.buildPacket(), ('<broadcast>', 67))

	print('DHCP Discover sent waiting for reply...\n')
	
	dhcp.settimeout(5)
	try:
		while True:
			data, addr = dhcp.recvfrom(2048) #receiving DHCPOffer packet  
			printSock(data)
			dhcp.sendto(buildREQUESTPacket(data), ('<broadcast>', 67))
			data, addr = dhcp.recvfrom(2048) #receiving DHCPACK packet  
			printSock(data)
			break
	except socket.timeout as e:
		print(e)

	dhcp.close()   #we close the socket
	sys.exit(0)
