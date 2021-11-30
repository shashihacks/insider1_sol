### Exercise 3: Routing and DNS

### Exercise 3: NAT

__Make sure that all the machines inside the three subnets (HAMBURG, PASSAU, MUNICH) can still reach webservers (http, https) on the Internet.__
- All machines are able to reach webservers


### 3.1 Explain

__Explain the functionality enabled by the keyword ’MASQUERADE’ in the context of the NAT configuration. Have you used it in your configuration?__

__Solution__ Masquerade NAT allows  to translate many IP addresses to one single IP address. masquerading in  NAT can be used to  hide one or more IP addresses on the  internal network. We can make use of this to expose one single IP to public and rest inside private network.
- Yes, we used it in our configuration.

### Exercise 4: Firewalling

__4.1 Set the firewalls to deny all connections by default.__  
__Solution__


- In our setup following  rules are setup in both firewalls.

```bash
iptables -P INPUT DROP   # Drop all incoming packets
```
```bash
iptables -P OUTPUT DROP   # Drop all outgoing packets
```
```bash
iptables -P FORWARD DROP   # Disable forwarding
```


__4.2 Prohibit machines on the internal network to provide services to the outside (e.g. an Internet reachable webserver on client-PA shall be prohibited), but allow all machines to use any service on any machine (internal subnets & Internet) as long as they initiate the connection__

__Solution__ Access to the internet is blocked by default

__1. Explain the differences between dynamic and static packet filtering. You should have used a dynamic filtering rule in the exercise above, state which and explain how it works.__
__Solution:__ 
- Static filtering :  In static filtering, firewall rule decises which packets are allowed or denied. Firewall evaluates each packet independently and has no impact with previous packets that have passed or denied.
- Dynamic filtering:  In dynamic filtering  firewall, it reacts to an event and create or update rules to handle with that particular event. It filters traffic with particular connection states, usually filtered by IP and PORT. For eg: Opening an FTP to outside world, PORT 21 must be left open permanently open so that outside clients can attempt establishing connection.
    - Dynamic filtering allows  port 21 to be opened at the start of an FTP session and then closes at the end of the session.


__2. Explain in what form dynamic filtering is better than static filtering?__

__Solution:__ The advantage of dynamic filtering is stateful packet inspection.  These stateful packet inspection filters the  exchange of packets, effectively by opening ports in the firewall for each communications session when needed basis, and then close the port as soon as they're no longer needed. One can easily allow or block the traffic accordingly.
- With this option one can switch events to inspect packets, which is useful in assisting security problems.

__4.3 Tell the firewall FW-south to REJECT all icmp requests from the PA Subnet and the Lab’s network. Test this by trying to ping from client-PA, but also try if the reverse succeeds (e.g. it shall still be possible to ping the computer client-PA from server-HH).__

__Solution__

```bash
iptables -A FORWARD -s 192.168.3.1/24 -p ICMP --icmp-type 8 -j REJECT
```
## Show PING responspose from server-HH



__4.4 Remove the ability to ping the firewalls themselves. This means you must tell the firewall to REJECT all icmp requests addressed to the FW-north and FW-south.__

- Firewall south
```bash
Iptables -A INPUT -p ICMP --icmp-type 0 -j DROP
```

- Firewall North

```bash
Iptables -A OUTPUT -p ICMP --icmp-type 8 -j DROP
```


__4.5 SSH sessions are only allowed to server-HH, all other ssh connections (despite of their destination or origin) shall be blocked.__

__Solution__

- Tell the firewall(s) to forward all `SSH` connections to `server-HH`

__North && South__

```bash
sudo iptables -A FORWARD -p tcp -d 192.168.1.3 --dport 22 -m state --state
NEW,ESTABLISHED -j ACCEPT
```

```bash
sudo iptables -A FORWARD -p tcp -s 192.168.1.3 -d --sport 22 -m state --state
ESTABLISHED -j ACCEPT
```
- Reject for all others

```bash
sudo iptables -A FORWARD -p tcp --sport 22 -j REJECT
```

__4.6 Make sure that the FW facing the Internet (Lab’s Net) prohibits that IP packets with a source address of the internal subnets arrive on the external interface (i.e. eth0 on FW-south).__

__Solution__

- On south firewall

```bash
sudo iptables -A OUTPUT -o enp0s3 -s 192.168.3.1/24 -j REJECT
sudo iptables -A OUTPUT -o enp0s3 -s 192.168.2.1/24 -j REJECT
sudo iptables -A OUTPUT -o enp0s3 -s 192.168.1.1/24 -j REJECT
```

__1. What is the reason to have FW rules that prohibit IP packets with a source address inside the internal subnet to leave to the external interface?__

- The above rule will block all connection to internet with source from internal subnet addresses. Firewall on the south uses `NAT` and connected to internet, hence internal network need not be exposed to connect to internet.In such case of accessing internet, the south firewall need to route  route the packets when trying to access the external network. 


### Exercise 5: Firewalling continued

__5.1 Give the iptables commands / rules that allow users on subnet PASSAU to view web pages (http, https) on a web server running in subnet HAMBURG (start/install web-server on server-HH). The rules shall block access to this server from the MUNICH subnet.__


__Solution__

1. Installing `Nginx` server (server-HH - 192.168.1.3 ).

```bash
$: sudo apt install nginx
```

- Passau subnet (`192.168.3.1/24`)

- **On firewall south on Both firewalls?**
```bash
sudo iptables -A FORWARD -p tcp -s 192.168.3.1/24 -d 192.168.1.1/24 -m multiport --dports 80,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
```

- Block from munich subnet

```bash
sudo iptables -A FORWARD -p tcp -s 192.168.2.1/24 -d 192.168.1.1/24 -m multiport --dports 80,443 -m conntrack --ctstate NEW,ESTABLISHED -j REJECT
```

- `-m conntrack`: allow the match based on connection state
- `--cstate`: parameter to define the list of states(like `new`, `established`, `closed`)



__5.2 Write the iptables commands / rules to allow HTTP and HTTPS traffic from the Internet (Lab’s Net) into the HAMBURG subnet. This includes access to a web server on server-HH.__


## check input and output interfaces

```bash
sudo iptables -A FORWARD -i enp0s3 -p tcp -d 10.1.0.0/24 -m multiport --dports 80,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -o enp0s2 -p tcp -s 10.1.0.0/24 -m multiport --dports 80,443 -m conntrack --ctstate ESTABLISHED -j ACCEPT
```


__5.3 Do not allow nor route any packets that try to use any host other than server-HH as their DNS nameserver. The DNS server port is 53. DNS can use both the tcp and udp protocols (udp by default).__



On both firewalls:
- Allow DNS (53) from server-HH - 192.168.1.3

```bash
iptables -A INPUT -p udp --dport 53 -s 192.168.1.3 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -s 192.168.1.3 -j ACCEPT
```
- Deny all other DNS requests

```bash
iptables -A INPUT -p udp --dport 53 -j DROP
iptables -A INPUT -p tcp --dport 53 -j DROP
```


__5.4 Can you still browse the internet? Explain why / why not. You still want all machines (in all three subnets) to browse the World wide Web (http/https). There are, roughly speaking, ways to accomplish this in regard to DNS resolution.__

__Solution__ No, we are unable to browse the internet, although connection to external IP addresses is still possible. This simply means that domain names can not be resolved.


We can use:
- To set in `Server-HH` one of Google’s DNS Server 8.8.8.8 as additional forwarder. The server is then forwarding DNS queries to a external server



__5.5 Log all traffic that attempts to connect to server-HH__
__Solution__

```bash
iptables -A FORWARD -m state --state NEW -d 192.168.1.3 -j LOG --log-prefix "New HH Connection: "
```

- log files can be viewed in

```bash
$: cat /var/log/syslog
```