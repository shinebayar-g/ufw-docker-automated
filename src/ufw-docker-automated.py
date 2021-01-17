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
            ufw_from = ["any"]
            ufw_deny_outgoing = None
            ufw_to = None

            container_port_dict = container.attrs['NetworkSettings']['Ports'].items()

            if container_network != 'default':
                # compose network
                container_ip = container.attrs['NetworkSettings']['Networks'][container_network]['IPAddress']
            else:
                # default network
                container_ip = container.attrs['NetworkSettings']['Networks']['bridge']['IPAddress']

            if 'UFW_MANAGED' in container.labels:
                ufw_managed = container.labels.get('UFW_MANAGED').capitalize()

            if ufw_managed == 'True':
                if 'UFW_FROM' in container.labels:
                    try:
                        ufw_from = [ip_network(ipnet) for ipnet in container.labels.get('UFW_FROM').split(';') if ipnet]
                    except ValueError as e:
                        print(f"ufw-docker-automated: Invalid UFW label: UFW_FROM={container.labels.get('UFW_FROM')} exception={e}")
                        ufw_from = None
                        pass

                if 'UFW_DENY_OUTGOING' in container.labels:
                    ufw_deny_outgoing = container.labels.get('UFW_DENY_OUTGOING').capitalize()

                if ufw_deny_outgoing == 'True' and 'UFW_TO' in container.labels:
                    try:
                        ufw_to = [ip_network(ipnet) for ipnet in container.labels.get('UFW_TO').split(';') if ipnet]
                    except ValueError as e:
                        print(f"ufw-docker-automated: Invalid UFW label: UFW_TO={container.labels.get('UFW_TO')} exception={e}")
                        ufw_to = None
                        pass

            if event_type == 'start' and ufw_managed == 'True':
                for key, value in container_port_dict:
                    if value:
                        container_port_num = list(key.split("/"))[0]
                        container_port_protocol = list(key.split("/"))[1]
                        if ufw_from:
                            for source in ufw_from:
                                # Allow incomming requests from whitelisted IPs or Subnets to the container
                                print(f"ufw-docker-automated: Adding UFW rule: allow from {source} to container {container.name} on port {container_port_num}/{container_port_protocol}")
                                subprocess.run([f"ufw route allow proto {container_port_protocol} \
                                                    from {source} \
                                                    to {container_ip} port {container_port_num}"],
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                            shell=True)
                                if ufw_deny_outgoing == 'True':
                                    # Allow the container to reply back to the client (if outgoing requests are denied by default)
                                    print(f"ufw-docker-automated: Adding UFW rule: allow reply from container {container.name} on port {container_port_num}/{container_port_protocol} to {source}")
                                    subprocess.run([f"ufw route allow proto {container_port_protocol} \
                                                        from {container_ip} port {container_port_num} \
                                                        to {source}"],
                                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                                shell=True)

                if ufw_deny_outgoing == 'True':
                    if ufw_to:
                        for destination in ufw_to:
                            # Allow outgoing requests from the container to whitelisted IPs or Subnets
                            print(f"ufw-docker-automated: Adding UFW rule: allow outgoing from container {container.name} to {destination}")
                            subprocess.run([f"ufw route allow from {container_ip} to {destination}"],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                        shell=True)
                    # Deny any other outgoing requests
                    print(f"ufw-docker-automated: Adding UFW rule: deny outgoing from container {container.name} to any")
                    subprocess.run([f"ufw route deny from {container_ip} to any"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                shell=True)

            if event_type == 'kill' and ufw_managed == 'True':
                ufw_length = subprocess.run(
                    [f"ufw status numbered | grep {container_ip} | wc -l"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                    shell=True)

                for i in range(int(ufw_length.stdout.strip().split("\n")[0])):
                    awk = "'{print $2}'"
                    ufw_status = subprocess.run(
                        [f"ufw status numbered | grep {container_ip} | awk -F \"[][]\" {awk} "],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                        shell=True)

                    # Removing any ufw rules that contains the container ip in it
                    ufw_num = ufw_status.stdout.strip().split("\n")[0]
                    ufw_delete = subprocess.run([f"yes y | ufw delete {ufw_num}"],
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                            shell=True)
                    ufw_delete_result = ufw_delete.stdout.split("\n")[1].strip()
                    print(f"ufw-docker-automated: Cleaning UFW rule: deleted rule '{ufw_delete_result}' for container {container.name}")


if __name__ == '__main__':
    manage_ufw()
