package ufwhandler

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog/log"
)

func checkIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func checkCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

func CreateUfwRule(ch <-chan *types.ContainerJSON, c *cache.Cache) {
	for container := range ch {
		containerName := strings.Replace(container.Name, "/", "", 1) // container name appears with prefix "/"
		containerIP := container.NetworkSettings.IPAddress
		containerID := container.ID[:12]
		// If docker-compose, container IP is defined here
		if containerIP == "" {
			networkMode := container.HostConfig.NetworkMode.NetworkName()
			if ip, ok := container.NetworkSettings.Networks[networkMode]; ok {
				containerIP = ip.IPAddress
			} else {
				log.Error().Msg("ufw-docker-automated: Couldn't detect the container IP address.")
				continue
			}
		}

		cachedContainer := TrackedContainer{
			Name:      containerName,
			IPAddress: containerIP,
			Labels:    container.Config.Labels,
		}

		c.Set(containerID, &cachedContainer, cache.NoExpiration)

		// Handle inbound rules
		for port, portMaps := range container.HostConfig.PortBindings {
			// List is non empty if port is published
			if len(portMaps) > 0 {
				ufwRules := []UfwRule{}
				if container.Config.Labels["UFW_ALLOW_FROM"] != "" {
					ufwAllowFromLabelParsed := strings.Split(container.Config.Labels["UFW_ALLOW_FROM"], ";")

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
					log.Info().Msg("ufw-docker-automated: Adding inbound rule: " + cmd.String())

					var stdout, stderr bytes.Buffer
					cmd.Stdout = &stdout
					cmd.Stderr = &stderr
					err := cmd.Run()

					if err != nil || stderr.String() != "" {
						log.Error().Err(err).Msg("ufw error: " + stderr.String())
					} else {
						log.Info().Msg("ufw: " + stdout.String())
					}
				}

				cachedContainer.UfwInboundRules = append(cachedContainer.UfwInboundRules, ufwRules...)
				// ufw route allow proto tcp from any to 172.17.0.2 port 80 comment "Comment"
				// ufw route allow proto <tcp|udp> <source> to <container_ip> port <port> comment <comment>
				// ufw route delete allow proto tcp from any to 172.17.0.2 port 80 comment "Comment"
				// ufw route delete allow proto <tcp|udp> <source> to <container_ip> port <port> comment <comment>
			}
		}

		// Handle outbound rules
		if container.Config.Labels["UFW_DENY_OUT"] == "TRUE" {

			if container.Config.Labels["UFW_ALLOW_TO"] != "" {
				ufwRules := []UfwRule{}
				ufwAllowToLabelParsed := strings.Split(container.Config.Labels["UFW_ALLOW_TO"], ";")

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
					log.Info().Msg("ufw-docker-automated: Adding outbound rule: " + cmd.String())

					var stdout, stderr bytes.Buffer
					cmd.Stdout = &stdout
					cmd.Stderr = &stderr
					err := cmd.Run()

					if err != nil || stderr.String() != "" {
						log.Error().Err(err).Msg("ufw error: " + stderr.String())
					} else {
						log.Info().Msg("ufw: " + stdout.String())
					}
				}

				cachedContainer.UfwOutboundRules = append(cachedContainer.UfwOutboundRules, ufwRules...)
			}

			// Handle deny all out
			cmd := exec.Command("sudo", "ufw", "route", "deny", "from", containerIP, "to", "any", "comment", containerName+":"+containerID)
			log.Info().Msg("ufw-docker-automated: Adding outbound rule: " + cmd.String())

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			err := cmd.Run()

			if err != nil || stderr.String() != "" {
				log.Error().Err(err).Msg("ufw error: " + stderr.String())
			} else {
				log.Info().Msg("ufw: " + stdout.String())
			}
		}
	}
}
