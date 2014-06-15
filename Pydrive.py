#!/usr/bin/env python
#Author: Jared Stroud
from scapy.all import *
import os

apList = [] 
interface = "wlan0"
f = open('wardriving.txt', 'a+') #Create/append to the file "wardriving.txt"

#Put wireless NIC into monitor mode.
def monMode():
	os.system("ifconfig " + interface + " down")
	os.system("iwconfig " + interface + " mode monitor")

#Capture beacon frames and display MAC + SSID
def pktCap(pkt):

	if pkt.haslayer(Dot11Beacon):	
		
		if pkt.addr2 not in apList: #If we haven't seen this access point append it to the list(apList) and write to a file.
			apList.append(pkt.addr2)
			accessPoint = ("Access Point MAC address: " + pkt.addr2 + " with SSID " + pkt.info)
			
			print accessPoint
			f.write(accessPoint)

monMode()
	
conf.iface = "mon0"
sniff(prn=pktCap)

f.close() #We're done writing for today...
