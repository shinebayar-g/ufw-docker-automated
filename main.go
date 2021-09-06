package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

func checkIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func checkCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

type ufwSource struct {
	CIDR    string
	comment string
}

func main() {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		panic(err)
	}

	filter := filters.NewArgs()
	filter.Add("type", "container")
	filter.Add("type", "network")

	messages, errors := cli.Events(ctx, types.EventsOptions{Filters: filter})

	for {
		select {
		case msg := <-messages:
			if msg.Type == "container" && msg.Action == "start" {

				if ufwManaged := msg.Actor.Attributes["UFW_MANAGED"]; strings.ToUpper(ufwManaged) == "TRUE" {
					container, err := cli.ContainerInspect(ctx, msg.ID)
					if err != nil {
						fmt.Println("ufw-docker-automated: Couldn't inspect container:", err)
						continue
					}

					for port, portMaps := range container.NetworkSettings.Ports {
						// List is non empty if port is published
						if len(portMaps) > 0 {
							ufwSourceList := []ufwSource{}
							if msg.Actor.Attributes["UFW_ALLOW_FROM"] != "" {
								ufwAllowFromList := strings.Split(msg.Actor.Attributes["UFW_ALLOW_FROM"], ";")

								for _, allowFrom := range ufwAllowFromList {
									ip := strings.Split(allowFrom, "-")

									if !checkIP(ip[0]) {
										if !checkCIDR(ip[0]) {
											fmt.Printf("ufw-docker-automated: address %s is not valid!\n", ip[0])
											continue
										}
									}

									if len(ip) > 1 {
										ufwSourceList = append(ufwSourceList, ufwSource{CIDR: ip[0], comment: fmt.Sprintf(" %s", ip[1])})
									} else {
										ufwSourceList = append(ufwSourceList, ufwSource{CIDR: ip[0]})
									}
								}
							} else {
								ufwSourceList = append(ufwSourceList, ufwSource{CIDR: "any"})
							}

							for _, source := range ufwSourceList {
								var stdout, stderr bytes.Buffer
								cmd := exec.Command("ufw", "route", "allow", "proto", port.Proto(), "from", source.CIDR, "to", container.NetworkSettings.IPAddress, "port", port.Port(), "comment", msg.Actor.Attributes["name"]+":"+msg.ID[:12]+source.comment)
								fmt.Println("ufw-docker-automated: Adding rule:", cmd)
								cmd.Stdout = &stdout
								cmd.Stderr = &stderr
								err := cmd.Run()

								if err != nil || stderr.String() != "" {
									fmt.Println("ufw:", err, stderr.String())
								} else {
									fmt.Println("ufw:", stdout.String())
								}
							}
							// ufw route allow proto tcp from any to 172.17.0.2 port 80 comment "Comment"
							// ufw route allow proto <tcp|udp> <source> to <container_ip> port <port> comment <comment>
						}
					}
				}
			}
			// We cannot get container network details once it's stopped, So
			// we're deleting ufw rules as soon as container receives stop signal before it's stopped.
			if msg.Type == "container" && msg.Action == "kill" {
				if ufwManaged := msg.Actor.Attributes["UFW_MANAGED"]; strings.ToUpper(ufwManaged) == "TRUE" {
					container, err := cli.ContainerInspect(ctx, msg.ID)
					if err != nil {
						fmt.Println("ufw-docker-automated: Couldn't inspect container:", err)
						continue
					}

					for port, portMaps := range container.NetworkSettings.Ports {
						// List is non empty if port is published
						if len(portMaps) > 0 {
							ufwSourceList := []ufwSource{}
							if msg.Actor.Attributes["UFW_ALLOW_FROM"] != "" {
								ufwAllowFromList := strings.Split(msg.Actor.Attributes["UFW_ALLOW_FROM"], ";")

								for _, allowFrom := range ufwAllowFromList {
									ip := strings.Split(allowFrom, "-")

									if !checkIP(ip[0]) {
										if !checkCIDR(ip[0]) {
											fmt.Printf("ufw-docker-automated: address %s is not valid!\n", ip[0])
											continue
										}
									}

									if len(ip) > 1 {
										ufwSourceList = append(ufwSourceList, ufwSource{CIDR: ip[0], comment: fmt.Sprintf(" %s", ip[1])})
									} else {
										ufwSourceList = append(ufwSourceList, ufwSource{CIDR: ip[0]})
									}
								}
							} else {
								ufwSourceList = append(ufwSourceList, ufwSource{CIDR: "any"})
							}

							for _, source := range ufwSourceList {
								var stdout, stderr bytes.Buffer
								cmd := exec.Command("ufw", "route", "delete", "allow", "proto", port.Proto(), "from", source.CIDR, "to", container.NetworkSettings.IPAddress, "port", port.Port(), "comment", msg.Actor.Attributes["name"]+":"+msg.ID[:12]+source.comment)
								fmt.Println("ufw-docker-automated: Deleting rule:", cmd)
								cmd.Stdout = &stdout
								cmd.Stderr = &stderr
								err := cmd.Run()

								if err != nil || stderr.String() != "" {
									fmt.Println("ufw:", err, stderr.String())
								} else {
									fmt.Println("ufw:", stdout.String())
								}
							}
							// ufw route delete allow proto tcp from any to 172.17.0.2 port 80 comment "Comment"
							// ufw route delete allow proto <tcp|udp> <source> to <container_ip> port <port> comment <comment>
						}
					}
				}
			}
		case err := <-errors:
			if err != nil {
				fmt.Println("ufw-docker-automated: Received an error:", err)
			}
		}
	}
}
