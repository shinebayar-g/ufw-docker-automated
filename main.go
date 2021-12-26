package main

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/shinebayar-g/ufw-docker-automated/ufwhandler"
)

func createClient() *client.Client {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		panic(err)
	}
	log.Println("ufw-docker-automated: Connecting to the Docker API. Listening for events..")
	return cli
}

func addFilters(client *client.Client, ctx *context.Context) (<-chan events.Message, <-chan error) {
	_, cancelContext := context.WithCancel(*ctx)
	cancelContext()
	filter := filters.NewArgs()
	filter.Add("type", "container")
	return client.Events(*ctx, types.EventsOptions{Filters: filter})
}

func main() {
	client := createClient()
	ctx := context.Background()
	messages, errors := addFilters(client, &ctx)

	createChannel := make(chan *ufwhandler.UfwEvent)
	deleteChannel := make(chan string)

	trackedContainers := make(map[string]*ufwhandler.TrackedContainer)

	go ufwhandler.CreateUfwRule(createChannel, trackedContainers)
	go ufwhandler.DeleteUfwRule(deleteChannel, trackedContainers)
	go ufwhandler.Cleanup(client, &ctx)

	for {
		select {
		case msg := <-messages:
			if ufwManaged := msg.Actor.Attributes["UFW_MANAGED"]; strings.ToUpper(ufwManaged) == "TRUE" {
				if msg.Action == "start" {
					container, err := client.ContainerInspect(ctx, msg.ID)
					if err != nil {
						log.Println("ufw-docker-automated: Couldn't inspect container:", err)
						continue
					}
					createChannel <- &ufwhandler.UfwEvent{Container: &container, Msg: &msg}
				}
				if msg.Action == "kill" {
					deleteChannel <- msg.ID[:12]
				}
			}
		case err := <-errors:
			if err != nil {
				log.Println("ufw-docker-automated: Docker socket error:", err)
				time.Sleep(5 * time.Second)
				log.Println("ufw-docker-automated: Reconnecting..")
				client = createClient()
				messages, errors = addFilters(client, &ctx)
			}
		}
	}
}
