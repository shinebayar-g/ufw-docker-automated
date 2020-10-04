#!/usr/bin/env python
import subprocess
import docker

client = docker.from_env()


def manage_ufw():
    for event in client.events(decode=True):

        event_type = event.get('status')

        if event_type == 'start' or event_type == 'kill':
            container = client.containers.get(event['id'])
            container_ip = container.attrs['NetworkSettings']['IPAddress']
            container_port_dict = container.attrs['NetworkSettings']['Ports'].items()
            ufw_managed = None
            port_num = None
            port_protocol = None

            if 'UFW_MANAGED' in container.labels:
                ufw_managed = container.labels.get('UFW_MANAGED').capitalize()

            if ufw_managed == 'True':
                for key, value in container_port_dict:
                    if value:
                        port_num = list(key.split("/"))[0]
                        port_protocol = list(key.split("/"))[1]

            if event_type == 'start' and ufw_managed == 'True':
                for key, value in container_port_dict:
                    if value:
                        port_num = list(key.split("/"))[0]
                        port_protocol = list(key.split("/"))[1]
                        print(f"Adding UFW rule: {port_num}/{port_protocol} of container {container.name}")
                        subprocess.run([f"sudo ufw route allow proto {port_protocol} \
                                            from any to {container_ip} \
                                            port {port_num}"],
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
                    print(f"Cleaning UFW rule: {port_num}/{port_protocol} of container {container.name}")
                    ufw_delete = subprocess.run([f"yes y | sudo ufw delete {ufw_num}"],
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                            shell=True)


if __name__ == '__main__':
    manage_ufw()
