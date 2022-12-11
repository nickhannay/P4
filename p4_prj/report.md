# Project 5

## 1.a) Commands

`h2 ping h3 -c1` :

!["ping"](1aa.png)

`pingall` :

!["pingall"](1ab.png)

`h1 traceroute h2` :

!['traceroute'](1ac.png)


---


## 1.b) Pcap dump

!['pcap dump'](1b.png)

**s1-eth1_in.pcap:**
This file shows all of the packets received from the eth1 interface at switch 1. In this case, all of the packets are from h1, since this is the interface h1 is connected to. The pingall command pings each host from each host in the network, so this pcap file shows the first three ping packets sent from h1, to h2, h3 and h4. It also shows the ping reply packets h1 sent back to each host.


**s1-eth1_out.pcap:**
This file shows all of the packets sent out through the eth1 interface of switch1. In this case, all of these packets are destined for h1 because h1 is connected on this interface. The output of this pcap file is the opposite of the previous pcap file, because it displays traffic going in the other direction. So as we can see, there are three reply's, corresponding to the three requests, and three requests corresponding to the three reply's.


---

## 1.c) Logging

!['logging'](1c.png)

14 bytes were parsed. These 14 bytes correspond to the ethernet header, and this is the only information the switch needs. The ethernet header contains the source and destination mac addresses, and the switch has rules installed relating to the mac addresses. The total size of the packet is 98 bytes:

    Ethernet header (14 bytes) + IP header (20 bytes) + ICMP header and data (64 bytes) = 98 bytes


---


## 2.a) Table Dump

!['table dump'](2a.png)


---


## 2.b) Format of s1-commands.txt

According to the P4 documentation, match-action rules are added to tables with the following syntax:

    table_add <table name> <action name> <match fields> => <action parameters> [priority]

The content of s1-commands.txt is in this format, as it adds 4 match-action rules to s1 corresponding to each host. 


---

## 2.c) Controller

!['output'](2c.png))

The output is the exact same as before. The command line file is used to statically configure p4 switches, in this case we start a controller that installs the rules for us, and this 'overwrites' the rules added statically. We can see the rules were initially added statically by looking at `s1_cli_output.log`:

!['cli](2c1.png)

If we want to use the the cli rules we would avoid starting the controller and just use the rules in the network configuration.

---



## **I.2: Packet Processing Pipeline**

## 1) Modifying the P4 program

commenting out dmac.apply() will not cause a compilation error. However it will produce a warning:

!['warning'](I.2.png)

This will not cause an error, but instead will not make use of the dmac table when preforming ingress processing of packets. This will result in no actions being applied to incoming packets, and they will be dropped:

!['dropped'](I.21.png)


If we look at the log for s1, we can see that there is no rules installed for any hosts, and so the ping request packet from h1 is sent out eth0 (connected to nothing) and effectively dropped:

!['log'](I.22.png)


As seen in the first screenshot, the dmac table is not included in the produced artifacts. Further, we can see there are various errors related to the missing dmac table such as:

!['error'](I.23.png)

---


## 2) Modifying the Control Plane


`pingall` : 

!['pingall'](I.24.png)


h1 sent 3 packets and received 0. We can see this by looking at the pcap files related to s1_eth1:

!['eth1'](I.25.png)

The three request packets sent by h1 make it to each host at h2, h3 and h4. However, the response packets are dropped, along with the ping request packets sent to h1. We can see that when processing packets destined for h1, there is no rule, and so it is dropped:

!['drop'](I.26.png)



---



## **II. Implement a Simple L2 Firewall

`pingall` :

!['pingall'](II.1.png)

All of the packets from h1 are dropped. We can see this by looking at the log file after running `h1 ping h2 -c1`:

!['ping'](II.2.png)


---


## **III. Implement a Simple IDS**


