#!/usr/bin/env python
import re
import docker
import subprocess
from ipaddress import ip_network

client = docker.from_env()

# implementation of a get method ontop __builtins__.list class
class _list(__builtins__.list):
    def get(self, index, default=None):
        try:
            return self[index] if self[index] else default
        except IndexError:
            return default

def to_string_port(port):
    if port.get(0) and port.get(1):
        return f"on port {int(port.get(0))}/{port.get(1)}"
    elif port.get(0):
        return f"on port {int(port.get(0))}"
    elif port.get(1):
        return f"on proto {port.get(1)}"
    else:
        return ""

def validate_port(port):
    if not port:
        return {}
    r = re.compile(r'^(\d+)?((/|^)(tcp|udp))?$')
    if r.match(port) is None:
        raise ValueError(f"'{port}' does not appear to be a valid port and protocol (examples: '80/tcp' or 'udp')")
    if port in ['tcp', 'udp']:
        return {'protocol': port, 'to_string_port': to_string_port(_list([None, port]))}
    port_and_protocol_split = _list(port.split('/'))
    if not (1 <= int(port_and_protocol_split.get(0)) <= 65535):
        raise ValueError(f"'{port}' does not appear to be a valid port number")
    return {'port': int(port_and_protocol_split.get(0)), 'protocol': port_and_protocol_split.get(1), 'to_string_port': to_string_port(port_and_protocol_split)}

def parse_ufw_to(label):
    output = []
    for item in label.split(';'):
        item_list = _list(item.split(':'))
        if len(item_list) == 2 or len(item_list) == 1:
            output += [{
                **{'ipnet': ip_network(item_list.get(0))}, 
                **validate_port(port=item_list.get(1))
            }]
    return output

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
                        ufw_to = parse_ufw_to(container.labels.get('UFW_TO'))
                    except ValueError as e:
                        print(f"ufw-docker-automated: Invalid UFW label: UFW_TO={container.labels.get('UFW_TO')} exception={e}")
                        ufw_to = None
                        pass

            if event_type == 'start' and ufw_managed == 'True':
                for key, value in container_port_dict:
                    if value and ufw_from:
                        container_port_num = list(key.split("/"))[0]
                        container_port_protocol = list(key.split("/"))[1]
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
                            print(f"ufw-docker-automated: Adding UFW rule: allow outgoing from container {container.name} to {destination.get('ipnet')} {destination.get('to_string_port', '')}")
                            destination_port = f"port {destination.get('port')}" if destination.get('port') else ""
                            destination_protocol = f"proto {destination.get('protocol')}" if destination.get('protocol') else ""
                            subprocess.run([f"ufw route allow {destination_protocol} \
                                                from {container_ip} \
                                                to {destination.get('ipnet')} {destination_port}"],
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
                    print(f"ufw-docker-automated: Cleaning UFW rule: container {container.name} deleted rule '{ufw_delete_result}'")


if __name__ == '__main__':
    manage_ufw()
