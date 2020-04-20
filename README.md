##### Project realised by Tristan Guerin and Grégoire Philippe
# README

## Set Up

After having executed the command in the file *Config-UbuntuGuest-VotreIPS* given in the resource of this
project, you have to execute the following commands in that order.

(***UbuntuDockerGuest-2***)

`apt update`

`apt install scapy`

`mkdir /home/script/`

Then copy the *attackDOS.py* script in the */home/script/* folder.


(***Ubuntu-guest-VotreIPs***)

`apt install scapy`

`apt install python-nfqueue`

`mkdir /home/script/`

`mkdir /home/logsIPS/`

`touch /home/logsIPS/mylog.txt`

Then copy the *interceptDOS.py* and *antiNMAP.py* scripts in the */home/script/* folder.


You can now start all start the web server and launch some *ping* commands to make sure everything is well set.

## Attack DOS

To test the DOS attack, first run the *interceptDOS.py* script on the *Ubuntu-guest-VotreIPs* machine, and then run the
*attackDOS.py* script on the *UbuntuDockerGuest-2* machine.

To run the *interceptDOS.py* script :

`python /home/script/interceptDOS.py <intervalInMilliseconds> <limitOfRequest>`<br/>
where `<intervalInMilliseconds>` is the interval of emission between two packets under we will consider
having a DOS attack currently taking place, and `<limitOfRequest>` the number of request maximum under this interval.

To run the *UbuntuDockerGuest-2* script :

`python /home/script/attackDOS.py <yourIP> <ipToDos> <numberOfRequest> [intervalInMilliseconds]`<br/>
where `<yourIP>` is the ip of the machine which launches the attack, `<ipToDos>` is the ip of the machine to attack,
`<numberOfRequest>` is the number of request to launch in a row and `[intervalInMilliseconds]` is the interval between two
emission (0 ms if not indicated).


## Scan NMAP

To test the NMAP scan attack, run the *antiNMAP.py* script on the *Ubuntu-guest-VotreIPs* machine, and then run a NMAP scan
from the *UbuntuDockerGuest-2* machine to the *Toolbox-2* machine.

To run the *antiNMAP.py* script :

`python /home/script/antiNMAP.py`

To run a NMAP scan :

`nmap -p <ports> <ipToScan>`<br/>
where `<ports>` is the ports to scan and `<ipToScan>` is the ip of the machine to scan.

<br/>After having launch the *antiNMAP.py* script and the NMAP scan, you can see the logs of the defense by running the following
command on the *Ubuntu-guest-VotreIPs* machine :

`cat /home/logsIPS/mylog.txt`
