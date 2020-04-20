"""
@author Tristan Guerin & Grégoire Philippe
@version 1
"""
## Intercept packets and displays their information

import nfqueue
from scapy.all import *
from scapy.layers.inet import IP
from datetime import datetime
import os
os.system("iptables -A INPUT -j NFQUEUE")
os.system("iptables -A OUTPUT -j NFQUEUE")
os.system("iptables -A FORWARD -j NFQUEUE")
def callback(test, payload):
    data = payload.get_data()
    pkt = IP(data)
    print("Got a packet : " + str(datetime.now()))
    print("  Source ip : " + str(pkt.src))
    print("  Dest ip : " + str(pkt.dst))
    print("  Source port : " + str(pkt.sport))
    print("  Dest port : " + str(pkt.dport))
    print("  Protocol : " + str(pkt.proto))
    print("  Flags :" + pkt.sprintf('%TCP.flags%'))

def main():
    q = nfqueue.queue()
    q.open()
    q.bind(socket.AF_INET)
    q.set_callback(callback)
    q.create_queue(0)
    try:
        q.try_run() # Main loop
    except KeyboardInterrupt:
        q.unbind(socket.AF_INET)
        q.close()
        os.system('iptables -F')
        os.system('iptables -X')
if __name__ == "__main__":
    main()
