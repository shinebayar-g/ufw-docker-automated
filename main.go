package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

type ufwSource struct {
	CIDR    string
	port    string
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

						// Example: 172.10.5.0-LAN or 172.10.5.0-80
						if len(ip) == 2 {
							if _, err := strconv.Atoi(ip[1]); err == nil {
								// case: 172.10.5.0-80
								ufwSourceList = append(ufwSourceList, ufwSource{CIDR: ip[0], port: ip[1]})
							} else {
								// case: 172.10.5.0-LAN
								ufwSourceList = append(ufwSourceList, ufwSource{CIDR: ip[0], comment: fmt.Sprintf(" %s", ip[1])})
							}
							// Example: 172.10.5.0-80-LAN
						} else if len(ip) == 3 {
							ufwSourceList = append(ufwSourceList, ufwSource{CIDR: ip[0], port: ip[1], comment: fmt.Sprintf(" %s", ip[2])})
							// Should be just IP address without comment or port specified.
						} else {
							ufwSourceList = append(ufwSourceList, ufwSource{CIDR: ip[0]})
						}
					}
				} else {
					ufwSourceList = append(ufwSourceList, ufwSource{CIDR: "any"})
				}

				containerIP := event.container.NetworkSettings.IPAddress
				// If docker-compose, container IP is defined here
				if containerIP == "" {
					networkMode := event.container.HostConfig.NetworkMode.NetworkName()
					containerIP = event.container.NetworkSettings.Networks[networkMode].IPAddress
				}

				for _, source := range ufwSourceList {
					var cmd *exec.Cmd
					var containerPort string

					if source.port == "" {
						containerPort = port.Port()
					} else {
						// Because we're overriding port.Proto() loop element with something static,
						// it'll create duplicate ufw rules. But ufw service handles that correctly.
						containerPort = source.port
					}

					if event.msg.Action == "start" {
						cmd = exec.Command("sudo", "ufw", "route", "allow", "proto", port.Proto(), "from", source.CIDR, "to", containerIP, "port", containerPort, "comment", event.msg.Actor.Attributes["name"]+":"+event.msg.ID[:12]+source.comment)
						fmt.Println("ufw-docker-automated: Adding rule:", cmd)
					} else {
						cmd = exec.Command("sudo", "ufw", "route", "delete", "allow", "proto", port.Proto(), "from", source.CIDR, "to", containerIP, "port", containerPort, "comment", event.msg.Actor.Attributes["name"]+":"+event.msg.ID[:12]+source.comment)
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

func createClient() *client.Client {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		panic(err)
	}
	return cli
}

func addFilters(cli *client.Client, ctx *context.Context) (<-chan events.Message, <-chan error) {
	_, cancelContext := context.WithCancel(*ctx)
	cancelContext()
	filter := filters.NewArgs()
	filter.Add("type", "container")
	filter.Add("type", "network")
	return cli.Events(*ctx, types.EventsOptions{Filters: filter})
}

func main() {
	cli := createClient()
	ctx := context.Background()
	messages, errors := addFilters(cli, &ctx)

	ch := make(chan ufwEvent)
	go handleUfwRule(ch)

	for {
		select {
		case msg := <-messages:
			// We cannot get container network details once it's stopped, So
			// we're deleting ufw rules as soon as container receives stop signal before it's stopped.
			if msg.Type == "container" && (msg.Action == "start" || msg.Action == "kill") {
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
				time.Sleep(3 * time.Second)
				fmt.Println("ufw-docker-automated: reconnecing")
				cli = createClient()
				messages, errors = addFilters(cli, &ctx)
			}
		}
	}
}
