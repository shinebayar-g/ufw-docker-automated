#!/usr/bin/env python
import subprocess
import docker
from ipaddress import ip_network
import re

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
    r = re.compile('^(\d+)?((/|^)(tcp|udp))?$')
    if r.match(port) is None:
        raise ValueError(f"'{port}' does not appear to be a valid port and protocol that matches '^(\d+)?((/|^)(tcp|udp))?$'")
    if port in ['tcp', 'udp']:
        return {'protocol': port, 'to_string_port': to_string_port(_list([None, port]))}
    port_and_protocol_split = _list(port.split('/'))
    if not (1 <= int(port_and_protocol_split.get(0)) <= 65535):
        raise ValueError(f"'{port}' does not appear to be a valid port number")
    return {'port': int(port_and_protocol_split.get(0)), 'protocol': port_and_protocol_split.get(1), 'to_string_port': to_string_port(port_and_protocol_split)}

def validate_hostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1] # strip exactly one dot from the right, if present
    labels = hostname.split(".")
    # the TLD must be not all-numeric
    if re.match(r"[0-9]+$", labels[-1]):
        return False
    allowed = re.compile("(?!-)[A-Z\d\-_]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in labels)

def validate_ip_network(ipnet):
    try:
        ip_network(ipnet)
        return True
    except ValueError as e:
        return False

# ipnet stands for ip or subnet
def validate_ipnet(ipnet):
    if not ipnet:
        return [{}]
    elif ipnet == "any":
        return [{'ipnet': "any"}]
    elif not validate_ip_network(ipnet=ipnet) and validate_hostname(hostname=ipnet):
        host_output = subprocess.run([f"host -t a {ipnet}"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                shell=True).stdout.strip().split("\n")
        return [{'ipnet': ip_network(_list(line.split("has address")).get(1).strip())} for line in host_output if _list(line.split("has address")).get(1)]
    else:
        return [{'ipnet': ip_network(ipnet)}]

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
            ufw_allow_from = None
            ufw_deny_outgoing = None
            ufw_allow_to = None

            container_port_dict = container.attrs['NetworkSettings']['Ports'].items()

            if container_network != 'default':
                # compose network
                container_ip = container.attrs['NetworkSettings']['Networks'][container_network]['IPAddress']
            else:
                # default network
                container_ip = container.attrs['NetworkSettings']['Networks']['bridge']['IPAddress']

            if 'UFW_MANAGED' in container.labels:
                ufw_managed = container.labels.get('UFW_MANAGED').capitalize()

            if 'UFW_ALLOW_FROM' in container.labels:
                try:
                    ufw_allow_from = [ip_network(ipnet) for ipnet in container.labels.get('UFW_ALLOW_FROM').split(';')]
                except ValueError as e:
                    print(f"Invalid UFW label: UFW_ALLOW_FROM={container.labels.get('UFW_ALLOW_FROM')} exception={e}")
                    ufw_allow_from = -1
                    pass

            if 'UFW_DENY_OUTGOING' in container.labels:
                ufw_deny_outgoing = container.labels.get('UFW_DENY_OUTGOING').capitalize()

            if 'UFW_ALLOW_TO' in container.labels:
                try:
                    ufw_allow_to = []
                    for item in container.labels.get('UFW_ALLOW_TO').split(';'):
                        item_split = _list(item.split(':'))
                        if len(item_split) == 2 or len(item_split) == 1:
                            ipnet_list = validate_ipnet(ipnet=item_split.get(0))
                            port_dict = validate_port(port=item_split.get(1))
                            ufw_allow_to += [{**ipnet_dict, **port_dict} for ipnet_dict in ipnet_list]
                except ValueError as e:
                    print(f"Invalid UFW label: UFW_ALLOW_TO={container.labels.get('UFW_ALLOW_TO')} exception={e}")
                    ufw_allow_to = None
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
                        if not ufw_allow_from:
                            # Allow incomming requests from any to the container
                            print(f"Adding UFW rule: allow from any to container {container.name} on port {container_port_num}/{container_port_protocol}")
                            subprocess.run([f"ufw route allow proto {container_port_protocol} \
                                                from any to {container_ip} \
                                                port {container_port_num}"],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                           shell=True)
                            if ufw_deny_outgoing == 'True':
                                # Allow the container to reply back to any client (if outgoing requests are denied by default)
                                print(f"Adding UFW rule: allow reply from container {container.name} on port {container_port_num}/{container_port_protocol} to any")
                                subprocess.run([f"ufw route allow proto {container_port_protocol} \
                                                    from {container_ip} port {container_port_num} to any"],
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                            shell=True)
                        elif isinstance(ufw_allow_from, list):
                            for source in ufw_allow_from:
                                # Allow incomming requests from whitelisted IPs or Subnets to the container
                                print(f"Adding UFW rule: allow from {source} to container {container.name} on port {container_port_num}/{container_port_protocol}")
                                subprocess.run([f"ufw route allow proto {container_port_protocol} \
                                                    from {source} to {container_ip} \
                                                    port {container_port_num}"],
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                            shell=True)
                                if ufw_deny_outgoing == 'True':
                                    # Allow the container to reply back to the client (if outgoing requests are denied by default)
                                    print(f"Adding UFW rule: allow reply from container {container.name} on port {container_port_num}/{container_port_protocol} to {source}")
                                    subprocess.run([f"ufw route allow proto {container_port_protocol} \
                                                        from {container_ip} port {container_port_num} to {source}"],
                                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                                shell=True)

                if ufw_deny_outgoing == 'True':
                    if ufw_allow_to:
                        for destination in ufw_allow_to:
                            # Allow outgoing requests from the container to whitelisted IPs or Subnets
                            print(f"Adding UFW rule: allow outgoing from container {container.name} to {destination.get('ipnet')} {destination.get('to_string_port')}")
                            destination_port = f"port {destination.get('port')}" if destination.get('port') else ""
                            destination_protocol = f"proto {destination.get('protocol')}" if destination.get('protocol') else ""
                            subprocess.run([f"ufw route allow {destination_protocol} \
                                                from {container_ip} to {destination.get('ipnet')} {destination_port}"],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                        shell=True)
                    # Deny any other outgoing requests
                    print(f"Adding UFW rule: deny outgoing from container {container.name} to any")
                    subprocess.run([f"ufw route deny from {container_ip} to any"],
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
                        [f"ufw status numbered | grep {container_ip} | awk -F \"[][]\" {awk} "],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                        shell=True)

                    # Removing any ufw rules that contains the container ip in it
                    ufw_num = ufw_status.stdout.strip().split("\n")[0]
                    print(f"Cleaning UFW rule: for container {container.name}")
                    ufw_delete = subprocess.run([f"yes y | ufw delete {ufw_num}"],
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                            shell=True)


if __name__ == '__main__':
    manage_ufw()
