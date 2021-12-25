package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
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
	container *types.ContainerJSON
	msg       *events.Message
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

func handleUfwRule(ch <-chan *ufwEvent) {
	for event := range ch {
		containerIP := event.container.NetworkSettings.IPAddress
		// If docker-compose, container IP is defined here
		if containerIP == "" {
			networkMode := event.container.HostConfig.NetworkMode.NetworkName()
			if ip, ok := event.container.NetworkSettings.Networks[networkMode]; ok {
				containerIP = ip.IPAddress
			} else {
				log.Println("ufw-docker-automated: Couldn't detect the container IP address.")
				continue
			}
		}

		// Handle inbound rules
		for port, portMaps := range event.container.HostConfig.PortBindings {
			// List is non empty if port is published
			if len(portMaps) > 0 {
				ufwAllowFromList := []ufwSource{}
				if event.msg.Actor.Attributes["UFW_ALLOW_FROM"] != "" {
					ufwAllowFromLabelParsed := strings.Split(event.msg.Actor.Attributes["UFW_ALLOW_FROM"], ";")

					for _, allowFrom := range ufwAllowFromLabelParsed {
						ip := strings.Split(allowFrom, "-")

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
								ufwAllowFromList = append(ufwAllowFromList, ufwSource{CIDR: ip[0], port: ip[1]})
							} else {
								// case: 172.10.5.0-LAN
								ufwAllowFromList = append(ufwAllowFromList, ufwSource{CIDR: ip[0], comment: fmt.Sprintf(" %s", ip[1])})
							}
							// Example: 172.10.5.0-80-LAN
						} else if len(ip) == 3 {
							ufwAllowFromList = append(ufwAllowFromList, ufwSource{CIDR: ip[0], port: ip[1], comment: fmt.Sprintf(" %s", ip[2])})
							// Should be just IP address without comment or port specified.
						} else {
							ufwAllowFromList = append(ufwAllowFromList, ufwSource{CIDR: ip[0]})
						}
					}
				} else {
					ufwAllowFromList = append(ufwAllowFromList, ufwSource{CIDR: "any"})
				}

				for _, source := range ufwAllowFromList {
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
						log.Println("ufw-docker-automated: Adding rule:", cmd)
					} else {
						cmd = exec.Command("sudo", "ufw", "route", "delete", "allow", "proto", port.Proto(), "from", source.CIDR, "to", containerIP, "port", containerPort, "comment", event.msg.Actor.Attributes["name"]+":"+event.msg.ID[:12]+source.comment)
						log.Println("ufw-docker-automated: Deleting rule:", cmd)
					}

					var stdout, stderr bytes.Buffer
					cmd.Stdout = &stdout
					cmd.Stderr = &stderr
					err := cmd.Run()

					if err != nil || stderr.String() != "" {
						log.Println("ufw:", err, stderr.String())
					} else {
						log.Println("ufw:", stdout.String())
					}
				}
				// ufw route allow proto tcp from any to 172.17.0.2 port 80 comment "Comment"
				// ufw route allow proto <tcp|udp> <source> to <container_ip> port <port> comment <comment>
				// ufw route delete allow proto tcp from any to 172.17.0.2 port 80 comment "Comment"
				// ufw route delete allow proto <tcp|udp> <source> to <container_ip> port <port> comment <comment>
			}
		}

		// Handle outbound rules
		if strings.ToUpper(event.msg.Actor.Attributes["UFW_DENY_OUT"]) == "TRUE" {

			if event.msg.Actor.Attributes["UFW_ALLOW_TO"] != "" {
				ufwAllowToList := []ufwSource{}
				ufwAllowToLabelParsed := strings.Split(event.msg.Actor.Attributes["UFW_ALLOW_TO"], ";")

				for _, allowTo := range ufwAllowToLabelParsed {
					ip := strings.Split(allowTo, "-")

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
							ufwAllowToList = append(ufwAllowToList, ufwSource{CIDR: ip[0], port: ip[1]})
						} else {
							// case: 172.10.5.0-LAN
							ufwAllowToList = append(ufwAllowToList, ufwSource{CIDR: ip[0], comment: fmt.Sprintf(" %s", ip[1])})
						}
						// Example: 172.10.5.0-80-LAN
					} else if len(ip) == 3 {
						ufwAllowToList = append(ufwAllowToList, ufwSource{CIDR: ip[0], port: ip[1], comment: fmt.Sprintf(" %s", ip[2])})
						// Should be just IP address without comment or port specified.
					} else {
						ufwAllowToList = append(ufwAllowToList, ufwSource{CIDR: ip[0]})
					}
				}

				for _, source := range ufwAllowToList {
					var cmd *exec.Cmd

					if event.msg.Action == "start" {
						if source.port == "" {
							cmd = exec.Command("sudo", "ufw", "route", "allow", "from", containerIP, "to", source.CIDR, "comment", event.msg.Actor.Attributes["name"]+":"+event.msg.ID[:12]+source.comment)
						} else {
							cmd = exec.Command("sudo", "ufw", "route", "allow", "from", containerIP, "to", source.CIDR, "port", source.port, "comment", event.msg.Actor.Attributes["name"]+":"+event.msg.ID[:12]+source.comment)
						}
						log.Println("ufw-docker-automated: Adding rule:", cmd)
					} else {
						if source.port == "" {
							cmd = exec.Command("sudo", "ufw", "route", "delete", "allow", "from", containerIP, "to", source.CIDR, "comment", event.msg.Actor.Attributes["name"]+":"+event.msg.ID[:12]+source.comment)
						} else {
							cmd = exec.Command("sudo", "ufw", "route", "delete", "allow", "from", containerIP, "to", source.CIDR, "port", source.port, "comment", event.msg.Actor.Attributes["name"]+":"+event.msg.ID[:12]+source.comment)
						}
						log.Println("ufw-docker-automated: Deleting rule:", cmd)
					}

					var stdout, stderr bytes.Buffer
					cmd.Stdout = &stdout
					cmd.Stderr = &stderr
					err := cmd.Run()

					if err != nil || stderr.String() != "" {
						log.Println("ufw:", err, stderr.String())
					} else {
						log.Println("ufw:", stdout.String())
					}
				}
			}

			// Handle deny all out
			var cmd *exec.Cmd

			if event.msg.Action == "start" {
				cmd = exec.Command("sudo", "ufw", "route", "deny", "from", containerIP, "to", "any", "comment", event.msg.Actor.Attributes["name"]+":"+event.msg.ID[:12])
				log.Println("ufw-docker-automated: Adding rule:", cmd)
			} else {
				cmd = exec.Command("sudo", "ufw", "route", "delete", "deny", "from", containerIP, "to", "any", "comment", event.msg.Actor.Attributes["name"]+":"+event.msg.ID[:12])
				log.Println("ufw-docker-automated: Deleting rule:", cmd)
			}

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			err := cmd.Run()

			if err != nil || stderr.String() != "" {
				log.Println("ufw:", err, stderr.String())
			} else {
				log.Println("ufw:", stdout.String())
			}
		}
	}
}

func createClient() *client.Client {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		panic(err)
	}
	log.Println("ufw-docker-automated: Connecting to the Docker API. Listening for events..")
	return cli
}

func addFilters(cli *client.Client, ctx *context.Context) (<-chan events.Message, <-chan error) {
	_, cancelContext := context.WithCancel(*ctx)
	cancelContext()
	filter := filters.NewArgs()
	filter.Add("type", "container")
	return cli.Events(*ctx, types.EventsOptions{Filters: filter})
}

func main() {
	cli := createClient()
	ctx := context.Background()
	messages, errors := addFilters(cli, &ctx)

	ch := make(chan *ufwEvent)
	go handleUfwRule(ch)

	for {
		select {
		case msg := <-messages:
			// We cannot get container network details once it's stopped, So
			// we're deleting ufw rules as soon as container receives stop signal before it's stopped.
			if msg.Action == "start" || msg.Action == "kill" {
				if ufwManaged := msg.Actor.Attributes["UFW_MANAGED"]; isUfwManaged(ufwManaged) {
					container, err := cli.ContainerInspect(ctx, msg.ID)
					if err != nil {
						log.Println("ufw-docker-automated: Couldn't inspect container:", err)
						continue
					}
					event := ufwEvent{container: &container, msg: &msg}
					ch <- &event
				}
			}
		case err := <-errors:
			if err != nil {
				log.Println("ufw-docker-automated: Docker socket error:", err)
				time.Sleep(5 * time.Second)
				log.Println("ufw-docker-automated: Reconnecting..")
				cli = createClient()
				messages, errors = addFilters(cli, &ctx)
			}
		}
	}
}
