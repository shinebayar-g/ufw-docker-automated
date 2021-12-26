package ufwhandler

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

func checkIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func checkCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

func CreateUfwRule(ch <-chan *UfwEvent, trackedContainers map[string]*TrackedContainer) {
	for event := range ch {
		containerName := event.Msg.Actor.Attributes["name"]
		containerIP := event.Container.NetworkSettings.IPAddress
		containerID := event.Msg.ID[:12]
		// If docker-compose, container IP is defined here
		if containerIP == "" {
			networkMode := event.Container.HostConfig.NetworkMode.NetworkName()
			if ip, ok := event.Container.NetworkSettings.Networks[networkMode]; ok {
				containerIP = ip.IPAddress
			} else {
				log.Println("ufw-docker-automated: Couldn't detect the container IP address.")
				continue
			}
		}

		trackedContainers[containerID] = &TrackedContainer{
			Name:      containerName,
			IPAddress: containerIP,
			Labels:    event.Container.Config.Labels,
		}

		c := trackedContainers[containerID]

		// Handle inbound rules
		for port, portMaps := range event.Container.HostConfig.PortBindings {
			// List is non empty if port is published
			if len(portMaps) > 0 {
				ufwRules := []UfwRule{}
				if event.Msg.Actor.Attributes["UFW_ALLOW_FROM"] != "" {
					ufwAllowFromLabelParsed := strings.Split(event.Msg.Actor.Attributes["UFW_ALLOW_FROM"], ";")

					for _, allowFrom := range ufwAllowFromLabelParsed {
						ip := strings.Split(allowFrom, "-")

						// First element should be always valid IP Address or CIDR
						if !checkIP(ip[0]) {
							if !checkCIDR(ip[0]) {
								log.Printf("ufw-docker-automated: Address %s is not valid!\n", ip[0])
								continue
							}
						}

						// Example: 172.10.5.0-LAN or 172.10.5.0-80
						if len(ip) == 2 {
							if _, err := strconv.Atoi(ip[1]); err == nil {
								// case: 172.10.5.0-80
								ufwRules = append(ufwRules, UfwRule{CIDR: ip[0], Port: ip[1], Proto: port.Proto()})
							} else {
								// case: 172.10.5.0-LAN
								ufwRules = append(ufwRules, UfwRule{CIDR: ip[0], Port: port.Port(), Proto: port.Proto(), Comment: fmt.Sprintf(" %s", ip[1])})
							}
							// Example: 172.10.5.0-80-LAN
						} else if len(ip) == 3 {
							ufwRules = append(ufwRules, UfwRule{CIDR: ip[0], Port: ip[1], Proto: port.Proto(), Comment: fmt.Sprintf(" %s", ip[2])})
						} else {
							// Example: 172.10.5.0
							ufwRules = append(ufwRules, UfwRule{CIDR: ip[0], Port: port.Port(), Proto: port.Proto()})
						}
					}
				} else {
					ufwRules = append(ufwRules, UfwRule{CIDR: "any", Port: port.Port(), Proto: port.Proto()})
				}

				for _, rule := range ufwRules {
					cmd := exec.Command("sudo", "ufw", "route", "allow", "proto", rule.Proto, "from", rule.CIDR, "to", containerIP, "port", rule.Port, "comment", containerName+":"+containerID+rule.Comment)
					log.Println("ufw-docker-automated: Adding rule:", cmd)

					var stdout, stderr bytes.Buffer
					cmd.Stdout = &stdout
					cmd.Stderr = &stderr
					err := cmd.Run()

					if err != nil || stderr.String() != "" {
						log.Println("ufw error:", err, stderr.String())
					} else {
						log.Println("ufw:", stdout.String())
					}
				}

				c.UfwInboundRules = append(c.UfwInboundRules, ufwRules...)
				// ufw route allow proto tcp from any to 172.17.0.2 port 80 comment "Comment"
				// ufw route allow proto <tcp|udp> <source> to <container_ip> port <port> comment <comment>
				// ufw route delete allow proto tcp from any to 172.17.0.2 port 80 comment "Comment"
				// ufw route delete allow proto <tcp|udp> <source> to <container_ip> port <port> comment <comment>
			}
		}

		// Handle outbound rules
		if strings.ToUpper(event.Msg.Actor.Attributes["UFW_DENY_OUT"]) == "TRUE" {

			if event.Msg.Actor.Attributes["UFW_ALLOW_TO"] != "" {
				ufwRules := []UfwRule{}
				ufwAllowToLabelParsed := strings.Split(event.Msg.Actor.Attributes["UFW_ALLOW_TO"], ";")

				for _, allowTo := range ufwAllowToLabelParsed {
					ip := strings.Split(allowTo, "-")

					// First element should be always valid IP Address or CIDR
					if !checkIP(ip[0]) {
						if !checkCIDR(ip[0]) {
							log.Printf("ufw-docker-automated: Address %s is not valid!\n", ip[0])
							continue
						}
					}

					// Example: 172.10.5.0-LAN or 172.10.5.0-80
					if len(ip) == 2 {
						if _, err := strconv.Atoi(ip[1]); err == nil {
							// case: 172.10.5.0-80
							ufwRules = append(ufwRules, UfwRule{CIDR: ip[0], Port: ip[1]})
						} else {
							// case: 172.10.5.0-LAN
							ufwRules = append(ufwRules, UfwRule{CIDR: ip[0], Comment: fmt.Sprintf(" %s", ip[1])})
						}
						// Example: 172.10.5.0-80-LAN
					} else if len(ip) == 3 {
						ufwRules = append(ufwRules, UfwRule{CIDR: ip[0], Port: ip[1], Comment: fmt.Sprintf(" %s", ip[2])})
					} else {
						// Example: 172.10.5.0
						ufwRules = append(ufwRules, UfwRule{CIDR: ip[0]})
					}
				}

				for _, rule := range ufwRules {
					var cmd *exec.Cmd

					if rule.Port == "" {
						cmd = exec.Command("sudo", "ufw", "route", "allow", "from", containerIP, "to", rule.CIDR, "comment", containerName+":"+containerID+rule.Comment)
					} else {
						cmd = exec.Command("sudo", "ufw", "route", "allow", "from", containerIP, "to", rule.CIDR, "port", rule.Port, "comment", containerName+":"+containerID+rule.Comment)
					}
					log.Println("ufw-docker-automated: Adding rule:", cmd)

					var stdout, stderr bytes.Buffer
					cmd.Stdout = &stdout
					cmd.Stderr = &stderr
					err := cmd.Run()

					if err != nil || stderr.String() != "" {
						log.Println("ufw error:", err, stderr.String())
					} else {
						log.Println("ufw:", stdout.String())
					}
				}

				c.UfwOutboundRules = append(c.UfwOutboundRules, ufwRules...)
			}

			// Handle deny all out
			cmd := exec.Command("sudo", "ufw", "route", "deny", "from", containerIP, "to", "any", "comment", containerName+":"+containerID)
			log.Println("ufw-docker-automated: Adding rule:", cmd)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			err := cmd.Run()

			if err != nil || stderr.String() != "" {
				log.Println("ufw error:", err, stderr.String())
			} else {
				log.Println("ufw:", stdout.String())
			}
		}

	}
}
