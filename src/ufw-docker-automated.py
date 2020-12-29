#!/usr/bin/env python
import subprocess
import docker
from ipaddress import ip_network

client = docker.from_env()


def manage_ufw():
    for event in client.events(decode=True):

        event_type = event.get('status')

        # container network is attached on start or stop event
        if event_type == 'start' or event_type == 'kill':
            container = None
            try:
                container = client.containers.get(event['id'])
            except docker.errors.NotFound as e:
                continue
            container_network = container.attrs['HostConfig']['NetworkMode']
            container_ip = None
            container_port_num = None
            container_port_protocol = None
            ufw_managed = None
            ufw_from = None

            container_port_dict = container.attrs['NetworkSettings']['Ports'].items()

            if container_network != 'default':
                # compose network
                container_ip = container.attrs['NetworkSettings']['Networks'][container_network]['IPAddress']
            else:
                # default network
                container_ip = container.attrs['NetworkSettings']['Networks']['bridge']['IPAddress']

            if 'UFW_MANAGED' in container.labels:
                ufw_managed = container.labels.get('UFW_MANAGED').capitalize()

            if 'UFW_FROM' in container.labels:
                try:
                    ufw_from = [ip_network(str(_sub)) for _sub in container.labels.get('UFW_FROM').split(';')]
                except ValueError as e:
                    print(f"Invalid UFW label: UFW_FROM={container.labels.get('UFW_FROM')} exception={e}")
                    ufw_from = -1
                    pass
                          
            if ufw_managed == 'True':
                for key, value in container_port_dict:
                    if value:
                        container_port_num = list(key.split("/"))[0]
                        container_port_protocol = list(key.split("/"))[1]

            if event_type == 'start' and ufw_managed == 'True':
                for key, value in container_port_dict:
                    if value:
                        container_port_num = list(key.split("/"))[0]
                        container_port_protocol = list(key.split("/"))[1]
                        if not ufw_from:
                            print(f"Adding UFW rule: {container_port_num}/{container_port_protocol} of container {container.name}")
                            subprocess.run([f"sudo ufw route allow proto {container_port_protocol} \
                                                from any to {container_ip} \
                                                port {container_port_num}"],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                           shell=True)
                        elif isinstance(ufw_from, list):
                            for subnet in ufw_from:
                                print(f"Adding UFW rule: {container_port_num}/{container_port_protocol} of container {container.name} from {subnet}")
                                subprocess.run([f"sudo ufw route allow proto {container_port_protocol} \
                                                    from {subnet} to {container_ip} \
                                                    port {container_port_num}"],
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                            shell=True)

            if event_type == 'kill' and ufw_managed == 'True':
                ufw_length = subprocess.run(
                    [f"sudo ufw status numbered | grep {container_ip} | wc -l"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                    shell=True)

                for i in range(int(ufw_length.stdout.strip().split("\n")[0])):
                    awk = "'{print $2}'"
                    ufw_status = subprocess.run(
                        [f"sudo ufw status numbered | grep {container_ip} | awk -F \"[][]\" {awk} "],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                        shell=True)

                    ufw_num = ufw_status.stdout.strip().split("\n")[0]
                    print(f"Cleaning UFW rule: {container_port_num}/{container_port_protocol} of container {container.name}")
                    ufw_delete = subprocess.run([f"yes y | sudo ufw delete {ufw_num}"],
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                            shell=True)


if __name__ == '__main__':
    manage_ufw()
