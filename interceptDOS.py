"""
@author Tristan Guerin & Grégoire Philippe
@version 1
"""
## Intercept packets and evaluates if it is a possible DOS attack

import nfqueue
from scapy.all import *
from scapy.layers.inet import IP
import sys
from datetime import datetime
import os

global interval
interval=0
global limit
limit=5
global requestIPs
requestIPs=[]
global blackList
blackList=[]

os.system("iptables -A INPUT -j NFQUEUE")
os.system("iptables -A OUTPUT -j NFQUEUE")
os.system("iptables -A FORWARD -j NFQUEUE")

"""
Returns a list of indexes corresponding of all
occurrences of a source ip in a given list
String ipSource : ip to search
List list : list to search in
"""
def getIpSource(ipSource,list):
    indexes = []
    for i in range(len(list)):
        if ipSource == list[i][0]:
            indexes.append(i)
    return indexes

"""
Returns the index in a list where a destination ip occurs
String ipDestination : ip to search
List list : list to search in
List indexes : list of indexes to search from
"""
def isAssociatedToThisDestination(ipDestination,list,indexes):
    for index in indexes:
        if(list[index][3]==ipDestination):
            return index
    return None

"""
Method which intercepts and analyses the packets, considers if a DOS attack
is happening and acting in consequences if so
"""
def callback(test, payload):
    global interval
    global limit
    global requestIPs
    global blackList

    data = payload.get_data()
    pkt = IP(data)
    print("Got a packet : "+str(datetime.now()))
    print("  Source ip : " + str(pkt.src))
    print("  Dest ip : " + str(pkt.dst))
    print("  Source port : "+str(pkt.sport))
    print("  Dest port : "+str(pkt.dport))
    print("  Protocol : "+str(pkt.proto))
    print("  Flags :"+pkt.sprintf('%TCP.flags%'))
    if(int(pkt.proto)!=6):
        # We let all non tcp messages go through without filtering
        payload.set_verdict(nfqueue.NF_ACCEPT)
    else:
        if(str(pkt.src) in blackList):
            print("This source has been blacklisted for DOSing")
            payload.set_verdict(nfqueue.NF_DROP)
        else:
            if(str(pkt[TCP].flags)=="20"):
                print("Response to a request")
                ### This is a response to a request, so we don't execute the checking procedure on this ip
                payload.set_verdict(nfqueue.NF_ACCEPT)
            else:
                if(str(pkt[TCP].flags)=="0"):
                    print("TCP synchronisation request")
                indexes = getIpSource(str(pkt.src),requestIPs)
                if(indexes==[]):
                    print("First request to this destination")
                    requestIPs.append([str(pkt.src),time.time()*1000,1,str(pkt.dst)])
                    payload.set_verdict(nfqueue.NF_ACCEPT)
                else:
                    index = isAssociatedToThisDestination(str(pkt.dst),requestIPs,indexes)
                    if(index==None):
                        print("First request to this destination.")
                        requestIPs.append([str(pkt.src), time.time() * 1000, 1, str(pkt.dst)])
                        payload.set_verdict(nfqueue.NF_ACCEPT)
                    elif(requestIPs[index][2]>=limit):
                        print(str(pkt.src) + " is blacklisted for DOS this destination")
                        blackList.append(str(pkt.src))
                        payload.set_verdict(nfqueue.NF_DROP)
                    else:
                        request = requestIPs[index]
                        lastRequest = request[1]
                        t = time.time()*1000
                        if ((t - lastRequest) < interval):
                            requestIPs[index] = [str(pkt.src),t,request[2]+1,str(pkt.dst)]
                        else:
                            requestIPs[index] = [str(pkt.src),t,request[2],str(pkt.dst)]
                        payload.set_verdict(nfqueue.NF_ACCEPT)
    print


def main():
    global interval
    global limit
    global requestIPs
    global blackList
    if (len(sys.argv) < 3):
        print("Usage : interceptDOS.py <intervalInMilliseconds> <limitOfRequest>")
        sys.exit()
    else:
        interval = float(sys.argv[1])
        limit = float(sys.argv[2])
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
