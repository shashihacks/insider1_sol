## Part 6: Real-Life Examples

### Exercise 1: Access to a Hotel WLAN

#### 1.1 Design and install a payment system which complies with the following requirements:


`Hostapd`: To create an unprotected WLAN

__Setup__

1. Set adapter to `master` mode.  
```bash
sudo iwconfig  mode master
```
2. Install

```bash
sudo apt-get install hostapd
```
3. Install  `DNSMASQ` to handle DHCP and DNS on the network.

```bash
sudo apt-get install dnsmasq
```
4. Modify `/etc/network/interfaces` file to have a static IP/

```bash
auto wlan0
iface wlan0 inet static
address 10.0.0.1
netmask 255.255.255.0
```

5. Start the `hostapd`

```bash
$: sudo systemctl start hostapd
```


__Setting up the DNS using bind9__

1. Installation

```bash
apt-get install bind9 bind9utils bind9-doc dnsutils -y
```

2. Edit `/etc/systemd/system/bind9.service` file to make the following changes.

```bash
[Service]
ExecStart=/usr/sbin/named -f -u bind -4
```

3. Restart `bind9`

```bash
systemctl restart bind9
```

__Configuring bind9__

4. Open `/etc/bind/named.conf.options` and uncomment/add following lines and save.

```bash
         forwarders {
                8.8.8.8;
         };
```

5. Next, define the zone for the domain, open `/etc/bind/named.conf.local`

```bash
zone "example.com" {
 type master;
 file "/etc/bind/forward.example.com";
};
```

__Configure forward lookup zone__

- Go to..
```bash
cd /etc/bind/
```
and execute  
```bash
cp db.127 reverse.example.com
```
- open `/etc/bind/forward.example.com` and make the following changes


```bash
$TTL    604800
@       IN      SOA     pay.example.com. root.test.example.com. (
                              2         ; Serial
                         604800         ; Refresh
                          86400         ; Retry
                        2419200         ; Expire
                         604800 )       ; Negative Cache TTL
@       IN      NS      test.example.com.
pay     IN      A       192.168.47.129
www     IN      A       192.168.47.129
@       IN      AAAA    ::1
````

- open `/etc/resolv.conf` and add the record

```bash
search example.com
nameserver 192.168.47.2 # gateway or DNS server IP
```

- restart `bind9`

```bash
$: systemctl restart bind9
```

- testing using `dig` command

![dig](images/dig.PNG)


__Setting up Coova Chilli Captive portal__




### Exercise 2: DNS tunneling

__2.1 Prepare a demo in which you show the hotel manager how IP over DNS tunneling works in their network and prepare appropriate explanations of your demo!__

__Solution__

DNS tunneling using `dnscat2`

__Preparing the Server__

```bash
$ git clone https://github.com/iagox86/dnscat2.git
$ cd dnscat2/server/
$ gem install bundler
$ bundle install
```

> Make sure to have `ruby` installed. (Available by default in kali linux)

- Running the server

![DNSCAT_server](images/dnscat_server.PNG)

- Running the client

![dnscat_client](images/dnscat_client.PNG)

A session will be established and communicates using an encrypted channel.

- Verifying traffic with `wireshark`

![dns_tunneling_wireshark](images/dns_tunneling_wireshark.PNG)


__2.2 Develop an automated mechanism which detects DNS tunneling in a general way.Do not base this mechanism on the detection of specific host addresses, domains, or IP ranges.__

__Solution__

Detecting using `SNORT`- an open source intrusion detection system.

- write an new rule under `/etc/snort/rules`


![snort_rules](images/snort_rules.png)


__2.3 Propose more than one solution which can fix the DNS tunneling vulnerability.__

__Solution__

__Method 1:__

- Changing the Chilli configuration tofix DNS tunneling

- Open `/etc/chilli/config` and uncomment
```bash
HS_DNSPARANOIA​=​on
```

That line will drop DNS packets containing something other than A, CNAME, SOA, or MX records.
 
 - Usually  tunneled traffic uses `TXT`.

__Method 2:__

Install a host-based Instrusion detection system(IDS)

__Method 3__

__Throttle DNS traffic__

In Chillispot, if the user is not logged in, all the requests are redirected to captive portal page, but captive portals enforce DNS server that answers with IP even when the user is not logged in. Which is normal in most hotspots, and there is no option to disable DNS service temporarily or completely.

- TO fix this problem, we can configure the hotspot create with `hostapd`, to throttle DNS traffic (say `5 kpbs`). This does not prevent DNS tunneling but makes it nearly unusable.




### Exercise 3: DNS Security

__3.1 Demonstrate a DNS poisoning attack to divert victims from the original payment server to a fake server you set up and which is similar to the payment server.__


__Solution__


__Our Setup__

![dns_poisoning_setup](images/dns_poisoning_setup.PNG)


To successfully carry out DNS pouisoning we chose to do, Man-in-the-middle attack using `ettercap`


__Setting up the environment__

- Create a fake payment page and host in Apache.
- Edit the `/var/www/html/index.html` to create one.

__Configuring ettercap__

1.  open `/etc/ettercap/etter.conf` file and change to `ec_uid = 0` and `ec_gid = 0`.


![ettercap_conf_1](images/ettercap_conf_1.PNG)

2. In the same file, uncomment the Iptables commands under linux

![ettercap_conf_2.PNG](images/ettercap_conf_2.PNG)

3. Open `/etc/ettercap/etter.dns` and add the dns record that need to point.

in my case:

`pay.example.com` running on `192.168.47.128` (Fake payment page where i want the victim to redirect)


__Running the `ettercap`__

![etter_dns](images/etter_dns.PNG)

- Open ettercap

```bash
$ sudo ettercap -G
```

![ettercap](images/ettercap.PNG)

- Select the interface, and click on `Accept`.
- Scan for hosts

![host_scan](images/host_scan.PNG) 

- Select the target and `Add to target 1` (`192.168.47.130`)

![host_list](images/host_list.PNG)

- Then load the DNS spoof plugin from the plugins menu, this will allow to poison the DNS.


__Simulating the Client__

- open the victim machine and browse  `pay.example.com`, which should redirect the user to our fake payment server.

__Result__

![fake_page](images/fake_page.PNG)


__3.2 Deploy DNSSec on the appropriate servers in your network and explain which security problems this solutions going to address and which problems are left open.__

__Solution:__

- For deploying we used `Webmin` to and configured our DNS server to `DNSSec` support.

__Installing `webmin`__


```bash
$: wget http://prdownloads.sourceforge.net/webadmin/webmin_1.984_all.deb
```
```bash
$: dpkg --install webmin_1.984_all.deb
```

- Now login to webmin at the URL: `http://localhost:10000`.



## Steps to setup DNSsec

![webmin_dnssec.jpg](images/webmin_dnssec.jpg)


- After setup test with `dig` for DNS keys and signature

![dnssec_keys.jpg](images/dnssec_keys.jpg)

- DNSSec solves integrity and  authenticity by providing digital singature(Provides Data origin authenticity​), and authenticates responses to domain name lookups. However, DNSsec does not provide any kind of privacy protection for those lookups.

__Issues with DNSSec__

1. Computaional overhead.
2. Does not provide privacy
3. Chain of trust problems: had to verify/trust each and every dns server that is setup in hirarchial fashion.
4. DNSSec timing issues: Signautes(RRSIG) are not generated for every dns query, but instaed they are generated with high TTL, allowing for freshness attack.



__3.3 If there are vulnerabilities which DNSSec does not mitigate, what other mechanisms could be deployed to prevent these attacks and how would you deploy them in your setup?__

__Solution__

1. We can  use TLS(DNS over TLS). This improves privacy and security between clients and resolvers.

