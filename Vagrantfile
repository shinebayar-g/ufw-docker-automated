# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|

  config.vm.define "ubuntu18-ufw-docker"
  config.vm.box = "hashicorp/bionic64"

  config.vm.synced_folder "./vagrant_data", "/vagrant_data"

  # Modify this line to match your environment
  config.vm.network "public_network", ip: "192.168.50.101", bridge: "Intel(R) Wi-Fi 6 AX200 160MHz"

  config.vm.provider "virtualbox" do |vb|
    vb.cpus = 2
    vb.memory = "2048"
    vb.name = "ubuntu18-ufw-docker"
  end

end
