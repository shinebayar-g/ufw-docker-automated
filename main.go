package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

type ufwSource struct {
	CIDR    string
	comment string
}

type ufwEvent struct {
	container types.ContainerJSON
	msg       events.Message
}

func checkIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func checkCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

func isUfwManaged(containerLabel string) bool {
	return strings.ToUpper(containerLabel) == "TRUE"
}

func handleUfwRule(ch <-chan ufwEvent) {
	for event := range ch {
		for port, portMaps := range event.container.HostConfig.PortBindings {
			// List is non empty if port is published
			if len(portMaps) > 0 {
				ufwSourceList := []ufwSource{}
				if event.msg.Actor.Attributes["UFW_ALLOW_FROM"] != "" {
					ufwAllowFromList := strings.Split(event.msg.Actor.Attributes["UFW_ALLOW_FROM"], ";")

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

				containerIP := event.container.NetworkSettings.IPAddress
				if containerIP == "" {
					networkMode := event.container.HostConfig.NetworkMode.NetworkName()
					containerIP = event.container.NetworkSettings.Networks[networkMode].IPAddress
				}

				for _, source := range ufwSourceList {
					var cmd *exec.Cmd
					if event.msg.Action == "start" {
						cmd = exec.Command("sudo", "ufw", "route", "allow", "proto", port.Proto(), "from", source.CIDR, "to", containerIP, "port", port.Port(), "comment", event.msg.Actor.Attributes["name"]+":"+event.msg.ID[:12]+source.comment)
						fmt.Println("ufw-docker-automated: Adding rule:", cmd)
					} else {
						cmd = exec.Command("sudo", "ufw", "route", "delete", "allow", "proto", port.Proto(), "from", source.CIDR, "to", containerIP, "port", port.Port(), "comment", event.msg.Actor.Attributes["name"]+":"+event.msg.ID[:12]+source.comment)
						fmt.Println("ufw-docker-automated: Deleting rule:", cmd)
					}
					var stdout, stderr bytes.Buffer
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
				// ufw route delete allow proto tcp from any to 172.17.0.2 port 80 comment "Comment"
				// ufw route delete allow proto <tcp|udp> <source> to <container_ip> port <port> comment <comment>
			}
		}
	}
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

	ch := make(chan ufwEvent)
	go handleUfwRule(ch)

	for {
		select {
		case msg := <-messages:
			if msg.Type == "container" && msg.Action == "start" {
				if ufwManaged := msg.Actor.Attributes["UFW_MANAGED"]; isUfwManaged(ufwManaged) {
					container, err := cli.ContainerInspect(ctx, msg.ID)
					if err != nil {
						fmt.Println("ufw-docker-automated: Couldn't inspect container:", err)
						continue
					}
					ch <- ufwEvent{container, msg}
				}
			}
			// We cannot get container network details once it's stopped, So
			// we're deleting ufw rules as soon as container receives stop signal before it's stopped.
			if msg.Type == "container" && msg.Action == "kill" {
				if ufwManaged := msg.Actor.Attributes["UFW_MANAGED"]; isUfwManaged(ufwManaged) {
					container, err := cli.ContainerInspect(ctx, msg.ID)
					if err != nil {
						fmt.Println("ufw-docker-automated: Couldn't inspect container:", err)
						continue
					}
					ch <- ufwEvent{container, msg}
				}
			}
		case err := <-errors:
			if err != nil {
				fmt.Println("ufw-docker-automated: Received an error:", err)
			}
		}
	}
}
