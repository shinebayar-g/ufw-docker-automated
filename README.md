# ufw-docker-automated

Manage Docker containers firewall with UFW!

If you use Docker, you may know docker's publish port function (`docker -p 8080:80` ) directly talks to **iptables** and update rules accordingly.
This conflicts with Ubuntu/Debian's `ufw` firewall manager and bypasses ufw rules.

Lot of [issues](https://github.com/moby/moby/issues/4737) were raised, but Docker didn't "fix" the issue.
Fortunately some smart people found the solution to this problem and my favorite one is [ufw-docker](https://github.com/chaifeng/ufw-docker). You can read more about it on the project's readme.

Original **ufw-docker** project is very easy to use, but it's static, doesn't track container IP changes. If original container's IP changes somehow _(e.g server reboot)_, your rule will be invalid.
This project solves that problem by listening to the Docker API events.

## Features

- Automate ufw-docker rules
- Automate docker container's firewall with labels
- Zero dependency, single binary installation
- Supports docker-compose

## Supported labels

| Label key      | Value / Syntax                                                  | Example                                                     |
| -------------- | --------------------------------------------------------------- | ----------------------------------------------------------- |
| UFW_MANAGED\*  | TRUE                                                            | `-l UFW_MANAGED=TRUE`                                       |
| UFW_ALLOW_FROM | CIDR/IP-SpecificPort-Comment , Semicolon separated, default=any | `-l UFW_ALLOW_FROM=192.168.3.0/24-LAN;10.10.0.50/32-53-DNS` |

## Example

```yml
# To use with docker-compose add labels: section to your docker-compose.yml file
version: '2.1'
services:
  nginx:
    image: nginx:alpine
    ports:
      - '8080:80'
      - '8081:81'
    labels:
      UFW_MANAGED: 'TRUE'
      UFW_ALLOW_FROM: '172.10.50.32;192.168.3.0/24;10.10.0.50/32-8080-LAN'
    networks:
      - my-network

networks:
  my-network:
    driver: bridge
```

```sh
# Allow from any
➜ docker run -d -p 8080:80 -p 8081:81 -l UFW_MANAGED=TRUE nginx:alpine

# Allow from certain IP address
➜ docker run -d -p 8082:82 -p 8083:83 -l UFW_MANAGED=TRUE -l UFW_ALLOW_FROM=192.168.3.0 nginx:alpine

# Allow from certain CIDR ranges
➜ docker run -d -p 8084:84 -p 8085:85 -l UFW_MANAGED=TRUE -l UFW_ALLOW_FROM="192.168.3.0/24;10.10.0.50/32" nginx:alpine

# Allow from certain IP address, CIDR ranges + comments
➜ docker run -d -p 8086:86 -p 8087:87 -l UFW_MANAGED=TRUE -l UFW_ALLOW_FROM="172.10.5.0;192.168.3.0/24-LAN;10.10.0.50/32-DNS" nginx:alpine

# Allow from certain IP address, CIDR ranges to different Port + comments
➜ docker run -d -p 8088:88 -p 8089:89 -p 8090:90 -l UFW_MANAGED=TRUE -l UFW_ALLOW_FROM="0.0.0.0/0-88-Internet;192.168.3.0/24-89-LAN;10.10.0.50-90" nginx:alpine

# Results
➜ sudo ufw status
Status: active

To                         Action      From
--                         ------      ----
22                         ALLOW       Anywhere

172.17.0.2 81/tcp          ALLOW FWD   Anywhere                   # crazy_keller:e875afe93296
172.17.0.2 80/tcp          ALLOW FWD   Anywhere                   # crazy_keller:e875afe93296
172.17.0.3 82/tcp          ALLOW FWD   192.168.3.0                # epic_lederberg:7c5001108663
172.17.0.3 83/tcp          ALLOW FWD   192.168.3.0                # epic_lederberg:7c5001108663
172.17.0.4 84/tcp          ALLOW FWD   192.168.3.0/24             # beautiful_taussig:089400a84073
172.17.0.4 84/tcp          ALLOW FWD   10.10.0.50                 # beautiful_taussig:089400a84073
172.17.0.4 85/tcp          ALLOW FWD   192.168.3.0/24             # beautiful_taussig:089400a84073
172.17.0.4 85/tcp          ALLOW FWD   10.10.0.50                 # beautiful_taussig:089400a84073
172.17.0.5 86/tcp          ALLOW FWD   172.10.5.0                 # funny_aryabhata:9eb642f07bde
172.17.0.5 86/tcp          ALLOW FWD   192.168.3.0/24             # funny_aryabhata:9eb642f07bde LAN
172.17.0.5 86/tcp          ALLOW FWD   10.10.0.50                 # funny_aryabhata:9eb642f07bde DNS
172.17.0.5 87/tcp          ALLOW FWD   172.10.5.0                 # funny_aryabhata:9eb642f07bde
172.17.0.5 87/tcp          ALLOW FWD   192.168.3.0/24             # funny_aryabhata:9eb642f07bde LAN
172.17.0.5 87/tcp          ALLOW FWD   10.10.0.50                 # funny_aryabhata:9eb642f07bde DNS
172.17.0.6 88/tcp          ALLOW FWD   Anywhere                   # awesome_leavitt:6ebdb0c87a56 Internet
172.17.0.6 89/tcp          ALLOW FWD   192.168.3.0/24             # awesome_leavitt:6ebdb0c87a56 LAN
172.17.0.6 90/tcp          ALLOW FWD   10.10.0.50                 # awesome_leavitt:6ebdb0c87a56
```

Once containers are stopped their ufw entries will be deleted.

## Installation

**Step 1**. Install [_ufw-docker_](https://github.com/chaifeng/ufw-docker#solving-ufw-and-docker-issues)'s firewall rules on your ufw configuration file.

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

**Step 3**. Download ufw-docker-automated binary

Download the [latest release](https://github.com/shinebayar-g/ufw-docker-automated/releases/latest) of the project.

**Step 4**. Run the app

To manage ufw rules, binary has to run as a root privileged user.

```
chmod +x ./ufw-docker-automated
./ufw-docker-automated
```

You'll most likely want to run this app in a background and at the startup of the system.
If you use **systemd** service manager _(Default since Ubuntu 16.04, Debian 8)_, here is an example.

Create and open new file on the following path `/lib/systemd/system/ufw-docker-automated.service` and copy the following content, don't forget to update the binary path.

```
[Unit]
Description=Ufw docker automated
Documentation=https://github.com/shinebayar-g/ufw-docker-automated
After=network-online.target ufw.service containerd.service
Wants=network-online.target
Requires=ufw.service

[Service]
# To manage ufw rules, binary has to run as a root or sudo privileged user.
User=ubuntu
# Provide /path/to/ufw-docker-automated
ExecStart=/usr/local/bin/ufw-docker-automated
Restart=always

[Install]
WantedBy=multi-user.target
```

Then reload the systemd.

```
sudo systemctl daemon-reload
sudo systemctl enable ufw-docker-automated
sudo systemctl start ufw-docker-automated
```

## Feedback

If you encounter any issues please feel free to open an issue.
