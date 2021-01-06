# ufw-docker-automated
Manage docker containers firewall with UFW!

If you use docker, you may know docker's publish port function (for example: `docker -p 8080:80` ) directly talks to **iptables** and update rules accordingly.
This conflicts with Ubuntu/Debian's `ufw` firewall manager and makes it useless. (Same on Centos/Redhat/Fedora's `firewalld`) In other words, ufw doesn't know about their secret talk, and only do what he knows. This creates a big confusion around UFW & Docker firewall issue.

To fix this issue lot of people [argued](https://github.com/docker/for-linux/issues/690) that it's either docker's problem or not. Nevertheless docker didn't "fix" the issue.
Fortunately some smart people found the solution to this problem and my favorite one is [ufw-docker](https://github.com/chaifeng/ufw-docker). You can read more about it on the project's readme.

Original **ufw-docker** project is very easy to use, but requires manual work and doesn't track container IP changes. If original container's IP changes somehow, your rule will be invalid.
To make it automated I hacked together some crap and it actually works. Now if you want to manage your docker container's firewall with your favorite tool `ufw` all you have to do is run your container with `UFW_MANAGED=TRUE` label. For example: `docker run -d -p 8080:80 -l UFW_MANAGED=TRUE nginx:alpine`

I've also added example code in an [examples](examples) folder.


**Step 1**. Install *ufw-docker*'s firewall rules on your ufw configuration file.

Open up `/etc/ufw/after.rules` file and add following code to the bottom of the file.

```
# BEGIN UFW AND DOCKER
*filter
:ufw-user-forward - [0:0]
:ufw-docker-logging-deny - [0:0]
:DOCKER-USER - [0:0]
-A DOCKER-USER -j ufw-user-forward

-A DOCKER-USER -j RETURN -s 10.0.0.0/8
-A DOCKER-USER -j RETURN -s 172.16.0.0/12
-A DOCKER-USER -j RETURN -s 192.168.0.0/16

-A DOCKER-USER -p udp -m udp --sport 53 --dport 1024:65535 -j RETURN

-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 192.168.0.0/16
-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 10.0.0.0/8
-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 172.16.0.0/12
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 192.168.0.0/16
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 10.0.0.0/8
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 172.16.0.0/12

-A DOCKER-USER -j RETURN

-A ufw-docker-logging-deny -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix "[UFW DOCKER BLOCK] "
-A ufw-docker-logging-deny -j DROP

COMMIT
# END UFW AND DOCKER
```

**Step 2**. Reload your ufw service to take effect of new configuration.

```
sudo ufw reload

# or

sudo service ufw restart

# or

sudo systemctl restart ufw
```

**Step 3**. Install my crap

Make sure you have python 3.6 and pip installed. Then you can either clone the repo or just copy the [ufw-docker-automated.py](src/ufw-docker-automated.py) file to your machine.
Then install the docker SDK for python by running: `pip install docker` and you're good to go.

**Step 4**. Create new systemd service entry

You may want to run this python script as background process and make it runnable on system boot to make sense of it. To do that, you can create new *systemd* service entry.

Create and open new file on the following path `/lib/systemd/system/ufw-docker-automated.service` and copy the following content, don't forget to update the script path.

```
[Unit]
Description=Ufw docker automated
Documentation=https://github.com/shinebayar-g/ufw-docker-automated
After=network-online.target ufw.service containerd.service
Wants=network-online.target
Requires=ufw.service

[Service]
# Script requires run as root or sudo user to manage ufw!
User=root
Environment=PYTHONUNBUFFERED=1
# Path to your python executable and actual location of the script
ExecStart=/usr/bin/python3 -u /home/ubuntu/ufw-docker-automated.py
Restart=always

[Install]
WantedBy=multi-user.target
```

**Step 5**. Enable the systemd service and start it

```
sudo systemctl daemon-reload
sudo systemctl enable ufw-docker-automated
sudo systemctl start ufw-docker-automated
```

**Step 6**. Profit

Run your containers with `UFW_MANAGED=TRUE` label. Script will automatically adds and removes necessary ufw rules based on the published ports.
For example:

```
➜  docker run -d -p 8080:80 -l UFW_MANAGED=TRUE nginx:alpine
13a6ef724d92f404f150f5796dabfd305f4e16a9de846a67e5e99ba53ed2e4e7
```

will add following entry to ufw list.

```
➜  sudo ufw status
Status: active

To                         Action      From
--                         ------      ----
22                         ALLOW       Anywhere
80/tcp                     ALLOW       Anywhere
443/tcp                    ALLOW       Anywhere

172.17.0.2 80/tcp          ALLOW FWD   Anywhere  <= this baby added
```

Note that you will access the container by its published port. For example: nginx is exposed at port 8080 here, not 80.

Once you stop the container, ufw entry will be gone.

```
➜  docker stop 13a6ef724d92
13a6ef724d92
```


```
➜  sudo ufw status
Status: active

To                         Action      From
--                         ------      ----
22                         ALLOW       Anywhere
80/tcp                     ALLOW       Anywhere
443/tcp                    ALLOW       Anywhere
```

**Step 7**. Hardening firewall rules with UFW_ALLOW_FROM

You can choose to restrict incoming traffic from specific IPs or Subnets.
For example :

```
➜  docker run -d -p 8080:80 -l UFW_MANAGED=TRUE -l "UFW_ALLOW_FROM=192.168.0.2;192.168.1.0/24" nginx:alpine
13a6ef724d92f404f150f5796dabfd305f4e16a9de846a67e5e99ba53ed2e4e7
```

will add following entry to ufw list.

```
➜  sudo ufw status
Status: active

To                         Action      From
--                         ------      ----
22                         ALLOW       Anywhere
80/tcp                     ALLOW       Anywhere
443/tcp                    ALLOW       Anywhere

172.17.0.2 80/tcp          ALLOW FWD   192.168.0.2     <= this baby added allowing only 192.168.0.2 to access nginx server
172.17.0.2 80/tcp          ALLOW FWD   192.168.1.0/24  <= this baby added allowing only 192.168.1.0/24 to access nginx server
```

**Step 8**. Hardening firewall rules with UFW_DENY_OUTGOING and UFW_ALLOW_TO

You can also choose to retrict outgoing traffic from specific IPs, Subnets or hostnames*.
For example with docker-compose :

```
version: '2.4'
services:
  nginx:
    image: nginx:alpine
    container_name: nginx
    labels:
      - UFW_MANAGED=true
      - UFW_ALLOW_FROM=192.168.0.0/24
      - UFW_DENY_OUTGOING=true
      - UFW_ALLOW_TO=any:53;deb.debian.org:80/tcp;security.debian.org:80/tcp;192.168.2.0/24;192.168.3.0/24:tcp
    ports:
      - 80:80
```

will add following entry to ufw list.

```
➜  sudo ufw status
Status: active

To                         Action      From
--                         ------      ----
22                         ALLOW       Anywhere                  
80/tcp                     ALLOW       Anywhere                  
443/tcp                    ALLOW       Anywhere                  

172.17.0.2 80/tcp          ALLOW FWD   192.168.0.0/24     <= this entry allows only 192.168.1.0/24 to access nginx server 
192.168.0.0/24             ALLOW FWD   172.17.0.2 80/tcp  <= this entry enables nginx server to reply back

53                         ALLOW FWD   172.17.0.2         <= this entry enables nginx to resolve dns queries to any ip

151.101.122.132 80/tcp     ALLOW FWD   172.17.0.2         <= those entries are the result of the commands :
151.101.192.204 80/tcp     ALLOW FWD   172.17.0.2         <= - 'host -t a deb.debian.org'
151.101.0.204 80/tcp       ALLOW FWD   172.17.0.2         <= - 'host -t a security.debian.org'
151.101.64.204 80/tcp      ALLOW FWD   172.17.0.2         <= to enable apt update in the container
151.101.128.204 80/tcp     ALLOW FWD   172.17.0.2

192.168.2.0/24             ALLOW FWD   172.17.0.2         <= this entry allow outgoing traffic to 192.168.2.0/24 subnet for all tcp and udp ports
192.168.3.0/24/tcp         ALLOW FWD   172.17.0.2/tcp     <= this entry allow outgoing traffic to 192.168.3.0/24 subnet for all tcp ports

Anywhere                   DENY FWD    172.17.0.2         <= this entry block any other outgoing requests
```

*Warning if the hostname changes the IP pool you'll need to restart the container in order to have an updated firewall.
This is why hostnames provided by dynamic dns will not work.