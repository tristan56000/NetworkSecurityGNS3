"""
@author Tristan Guerin & Grégoire Philippe
@version 1
"""
#!/usr/bin/env python
# -*-coding:Latin-1 -*

import nfqueue
from scapy.all import *
import os
import time

# All packets that should be filtered :

# If you want to use it as a reverse proxy for your machine
iptablesIN = "iptables -A INPUT -j NFQUEUE"
iptablesOUT = "iptables -A OUTPUT -j NFQUEUE"
iptablesFOR = "iptables -A FORWARD -j NFQUEUE"

print("Adding iptable rules :")
print(iptablesIN)
print(iptablesOUT)
print(iptablesFOR)
os.system(iptablesIN)
os.system(iptablesOUT)
os.system(iptablesFOR)

# If you want to use it for MITM attacks, set ip_forward=1 :
#print("Set ipv4 forward settings : ")
#os.system("sysctl net.ipv4.ip_forward=1")

global pre_portRequest
pre_portRequest={}
global blockIP
blockIP={}
global ipContact
ipContact={}

def callback(test,payload):
        global pre_portRequest
        global blockIP
        global ipContact
        block=False

        os.system("echo 'blocked : '>> /home/logsIPS/mylog.txt")
        os.system("echo "+ str(ipContact) + ">> /home/logsIPS/mylog.txt")
        os.system('echo "port request : ">> /home/logsIPS/mylog.txt')
        os.system('echo '+ str(pre_portRequest) +'>> /home/logsIPS/mylog.txt')
        # Here is where the magic happens.
        data = payload.get_data()
        pkt = IP(data)
        os.system("echo Got a packet ! source ip : " + str(pkt.src) + " to "+str(pkt.dst)+" >> /home/logsIPS/mylog.txt")
        #print pkt.show2()
        #print("port request :"+str(pkt.payload.dport))
        sourceIP=str(pkt.src)
        destIP=str(pkt.dst)
        #pkt.show2()
        #print pkt.__dict__

        # si IP source dans notre liste d'IP blocke
        if sourceIP in blockIP:
                os.system("echo ip blocked : "+str(sourceIP) + "since "+str(time.time()-blockIP[sourceIP])+" >> /home/logsIPS/mylog.txt")
                # si le temps de blocage est depasse   (30 secondes)
                if ((time.time()-blockIP[sourceIP]) > 30) :
                        # on supprime l'IP de la liste
                        del blockIP[sourceIP]
                else  :
                        # le temps de blocage n'est pas depasse, on block
                        block = True

        # si on block
        if block==True :
                # on drop la requete
                payload.set_verdict(nfqueue.NF_DROP) ######
                return
        else :
                if sourceIP != "192.168.0.100":
                        # si on ne block pas, si le protocole est tcp
                        if pkt.proto == 6:
                                os.system("echo request on port : "+str(pkt.payload.dport)+" >> /home/logsIPS/mylog.txt")
                                if (str(pkt.payload.dport)=='443' or str(pkt.payload.dport)=='80'):
                                        payload.set_verdict(nfqueue.NF_ACCEPT)
                                        return
				if sourceIP in ipContact:
                                	# si l'ip nous a deja contacter
                                	if (time.time()-ipContact[sourceIP] > 30):
                                		# on change son temps de contact
                                  		ipContact[sourceIP]=time.time()
                                		#on redefinit son port de contact
                               			pre_portRequest[sourceIP]=pkt.payload.dport
                                else :
                                        # si l'ip ne nous a jamais contacter
                                        # on l'ajoute dans nos contact avec le temps
                                        ipContact[sourceIP]=time.time()
                                        # on l'ajoute dans le port request
                                        os.system("echo new contact : "+str(sourceIP)+" "+str(pkt.payload.dport)+" >> /home/logsIPS/mylog.txt")
                                        pre_portRequest[sourceIP]=pkt.payload.dport

                                # si le port demande est different
                                if(pre_portRequest[sourceIP] != pkt.payload.dport):
                                        # on suppose que c'est un scan nmap
                                        os.system("echo /!\ ALERT SCAN NMAP >> /home/logsIPS/mylog.txt")
                                        # on ajoute l'ip source a blocker
                                        blockIP[sourceIP]= time.time()
                                        # on drop le paquet
                                        payload.set_verdict(nfqueue.NF_DROP) ######
                                        return
                                else :
                                        payload.set_verdict(nfqueue.NF_ACCEPT)
                                        return

                        else :
                                payload.set_verdict(nfqueue.NF_ACCEPT)
                                return
                else :
                        payload.set_verdict(nfqueue.NF_ACCEPT)
                        return

        # If you want to modify the packet, copy and modify it with scapy then do :
        #payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(packet), len(packet))


def main():
    # This is the intercept
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
        print("Flushing iptables.")
        # This flushes everything, you might wanna be careful
        os.system('iptables -F')
        os.system('iptables -X')
        os.system('iptables -t nat -A POSTROUTING -o eth2 -j MASQUERADE')


if __name__ == "__main__":
    main()


