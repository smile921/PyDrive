#!/usr/bin/env python
#Author: Jared Stroud
from scapy.all import *
import os

apList[] 
f = open('wardriving.txt', 'a+') #Create/append to the file "wardriving.txt"

#Put wireless NIC into monitor mode.
def monMode():
	os.system("ifconfig wlan0 down")
	os.system("iwconfig wlan0 mode monitor")

#Capture beacon frames and display MAC + SSID
def pktCap(pkt):

	if pkt.haslayer(Dot11Beacon):	
		
		if pkt.addr2 not in apList: #If we haven't seen this access point append it to the list(apList) and write to a file.
			apList.append(pkt.addr2)
			accessPoint = ("Access Point MAC address: " + pjt.addr2 + " with SSID " + pkt.info)
			
			print accessPoint
			f.write(accessPoint)
	

monmode()
	
conf.iface = "mon0"
sniff(prn=pktCap)

f.close() #We're done writing for today...
