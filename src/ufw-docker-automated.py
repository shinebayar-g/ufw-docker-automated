#!/usr/bin/env python
import subprocess
import docker
from ipaddress import ip_network
import re

client = docker.from_env()

class _list(__builtins__.list):
    def get(self, index, default=None):
        try:
            return self[index] if self[index] else default
        except IndexError:
            return default

class _tuple(__builtins__.tuple):
    def get(self, index, default=None):
        try:
            return self[index] if self[index] else default
        except IndexError:
            return default

def validate_port(port):
    if not port:
        return _tuple([None, None])

    _port = str(port)
    r = re.compile('^(\d+)?(/tcp|/udp)?$')
    if r.match(_port) is None:
        raise ValueError(f"Port format is invalid {_port} it must match '^(\d+)?(/tcp|/udp)?$'")
    _port_tuple = _list(_port.split('/'))
    return _tuple([_port_tuple.get(0), _port_tuple.get(1)])

def validate_hostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1] # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

def validate_ip_network(ip):
    try:
        ip_network(ip)
        return True
    except ValueError as e:
        return False

def validate_network(network):
    if not network:
        return _list()

    _network = str(network)
    if _network == "any":
        return _list(["any"])
    elif not validate_ip_network(_network) and validate_hostname(_network):
        host_output = subprocess.run([f"host -t a {_network}"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                    shell=True).stdout.strip().split("\n")
        return _list([ip_network(_list(line.split("has address")).get(1).strip()) for line in host_output if _list(line.split("has address")).get(1)])
    else:
        return _list([ip_network(_network)])

def format_destination_port(_to):
    if _to.get(1) and _to.get(2):
        return f" on port {_to.get(1)}/{_to.get(2)}"
    elif _to.get(1):
        return f" on port {_to.get(1)}"
    elif _to.get(2):
        return f" on proto {_to.get(2)}"
    else:
        return ""

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

            if 'UFW_FROM' in container.labels:
                try:
                    ufw_from = [ip_network(str(_sub)) for _sub in container.labels.get('UFW_FROM').split(';')]
                except ValueError as e:
                    print(f"Invalid UFW label: UFW_FROM={container.labels.get('UFW_FROM')} exception={e}")
                    ufw_from = -1
                    pass

            if 'UFW_DENY_OUTGOING' in container.labels:
                ufw_deny_outgoing = container.labels.get('UFW_DENY_OUTGOING').capitalize()

            if 'UFW_TO' in container.labels:
                try:
                    ufw_to = _list()
                    for _to in container.labels.get('UFW_TO').split(';'):
                        _to_list = _list(_to.split(':'))
                        if len(_to_list) == 2 or len(_to_list) == 1:
                            _to_sub = validate_network(_to_list.get(0))
                            _to_port = validate_port(_to_list.get(1))
                            ufw_to += [_tuple([_ip, _to_port.get(0), _to_port.get(1)]) for _ip in _to_sub]
                except ValueError as e:
                    print(f"ufw-docker-automated: Invalid UFW label: UFW_TO={container.labels.get('UFW_TO')} exception={e}")
                    ufw_to = None
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
                            print(f"Adding UFW rule: allow from any to container {container.name} on port {container_port_num}/{container_port_protocol}")
                            subprocess.run([f"sudo ufw route allow proto {container_port_protocol} \
                                                from any to {container_ip} \
                                                port {container_port_num}"],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                           shell=True)
                            if ufw_deny_outgoing == 'True':
                                # Allow container to reply back to the client
                                print(f"Adding UFW rule: allow reply from container {container.name} on port {container_port_num}/{container_port_protocol} to any")
                                subprocess.run([f"ufw route allow proto {container_port_protocol} \
                                                    from {container_ip} port {container_port_num} to any"],
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                            shell=True)
                        elif isinstance(ufw_from, list):
                            for subnet in ufw_from:
                                print(f"Adding UFW rule: allow from {subnet} to container {container.name} on port {container_port_num}/{container_port_protocol}")
                                subprocess.run([f"sudo ufw route allow proto {container_port_protocol} \
                                                    from {subnet} to {container_ip} \
                                                    port {container_port_num}"],
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                            shell=True)
                                if ufw_deny_outgoing == 'True':
                                    # Allow container to reply back to the client
                                    print(f"Adding UFW rule: allow reply from container {container.name} on port {container_port_num}/{container_port_protocol} to {subnet}")
                                    subprocess.run([f"ufw route allow proto {container_port_protocol} \
                                                        from {container_ip} port {container_port_num} to {subnet}"],
                                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                                shell=True)

                if ufw_deny_outgoing == 'True':
                    if ufw_to:
                        for _to in ufw_to:
                            print(f"Adding UFW rule: allow outgoing from container {container.name} to {_to.get(0)}{format_destination_port(_to)}")
                            destination_port_num = f"port {_to.get(1)}" if _to.get(1) else ""
                            destination_port_protocol = f"proto {_to.get(2)}" if _to.get(2) else ""
                            subprocess.run([f"ufw route allow {destination_port_protocol} \
                                                from {container_ip} to {_to.get(0)} {destination_port_num}"],
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
                        [f"sudo ufw status numbered | grep {container_ip} | awk -F \"[][]\" {awk} "],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                        shell=True)

                    ufw_num = ufw_status.stdout.strip().split("\n")[0]
                    print(f"Cleaning UFW rule: for container {container.name}")
                    ufw_delete = subprocess.run([f"yes y | sudo ufw delete {ufw_num}"],
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                            shell=True)


if __name__ == '__main__':
    manage_ufw()
