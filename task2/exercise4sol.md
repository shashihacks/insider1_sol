## Task Sheet 2
Authors: Omar, Shashi, Lorant

## Exercise 4: Hping3

###  4.1 Briefly explain what the PING utility is used for.


PING utility is used to check if a device or a domain is reachable and operating or not.
We used 2 VMs one of them is naive VM and another impersonating VM which will send ping requests to the naive machine but it will spoof the IP address and it will use the host machine IP address and this will be peformed using Hping3 as shown in the image below


![hping3request](images/hping3request.PNG)

The IP address of the host machine is 192.168.0.3 which will be used to spoof the naive machine and 192.168.0.44 is the IP address of the naive machine.

After sending the ping requests we check wireshark and we can see it can see the requests are coming from the host machine 192.168.0.3 while it is coming from  the impersonating VM 

![hping3wireshark](images/hping3wireshark.PNG)

#### 4.2 What command did you use to create the spoofing PING request? Explain it.


```bash
$ sudo hping3 -a 192.168.0.3 192.168.0.44 --icmp 
```
The ip adress after -a is the spoofing ip adress and the second ip address is the destination address

##### 4.3 What happens with the ICMP packets that are sent from the NaiveVM to the Host Machine?

The reply sent from the naive machine will be dropped by the host machine as the host actually didn't request them to receive an reply


