#!/bin/bash

GREEN='\033[39;42m'
NOCOLOR='\033[0m'

sudo wget -O /usr/local/bin/ufw-docker \
  https://github.com/chaifeng/ufw-docker/raw/master/ufw-docker
sudo chmod +x /usr/local/bin/ufw-docker
ufw-docker install
ufw-docker status

sudo ufw reload

wget -c https://github.com/shinebayar-g/ufw-docker-automated/releases/download/v0.11.0/ufw-docker-automated_0.11.0_linux_amd64.tar.gz \
-O - | sudo tar -xz -C /usr/local/bin/

echo "[Unit]
      Description=Ufw docker automated
      Documentation=https://github.com/shinebayar-g/ufw-docker-automated
      After=network-online.target ufw.service containerd.service
      Wants=network-online.target
      Requires=ufw.service

      [Service]
      # To manage ufw rules, binary has to run as a root or sudo privileged user.
      User=root
      # Provide /path/to/ufw-docker-automated
      ExecStart=/usr/local/bin/ufw-docker-automated
      Restart=always

      [Install]
      WantedBy=multi-user.target" > /lib/systemd/system/ufw-docker-automated.service

sudo systemctl daemon-reload
sudo systemctl enable ufw-docker-automated
sudo systemctl start ufw-docker-automated
sudo systemctl status ufw-docker-automated --no-pager
echo -e "${GREEN}Docker ufw integration was successfully installed${NOCOLOR}"
exit 0
