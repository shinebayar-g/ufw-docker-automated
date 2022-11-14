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

func createClient() (*context.Context, *client.Client, error) {
	ctx := context.Background()
	client, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return &ctx, client, err
	}
	_, err = client.Info(ctx)
	return &ctx, client, err
}

func streamEvents(ctx *context.Context, c *client.Client) (<-chan events.Message, <-chan error) {
	filter := filters.NewArgs()
	filter.Add("type", "container")
	return c.Events(*ctx, types.EventsOptions{Filters: filter})
}

func reconnect() (*context.Context, *client.Client, error) {
	var ctx *context.Context
	var client *client.Client
	var err error
	for {
		time.Sleep(5 * time.Second)
		log.Println("ufw-docker-automated: Trying to reconnect..")
		ctx, client, err = createClient()
		if err == nil {
			break
		}
	}
	log.Println("ufw-docker-automated: Reconnected to the Docker Engine.")
	return ctx, client, err
}

func main() {
	ctx, client, err := createClient()
	if err != nil {
		log.Println("ufw-docker-automated: Client error:", err)
		ctx, client, err = reconnect()
	} else {
		log.Println("ufw-docker-automated: Connected to the Docker Engine.")
	}
	createChannel := make(chan *types.ContainerJSON)
	deleteChannel := make(chan string)

	trackedContainers := make(map[string]*ufwhandler.TrackedContainer)

	go ufwhandler.CreateUfwRule(createChannel, trackedContainers)
	go ufwhandler.DeleteUfwRule(deleteChannel, trackedContainers)
	go ufwhandler.Cleanup(client, ctx)
	go ufwhandler.Sync(createChannel, client, ctx)

	messages, errors := streamEvents(ctx, client)
	for {
		select {
		case msg := <-messages:
			if ufwManaged := msg.Actor.Attributes["UFW_MANAGED"]; strings.ToUpper(ufwManaged) == "TRUE" {
				if msg.Action == "start" {
					container, err := client.ContainerInspect(*ctx, msg.ID)
					if err != nil {
						log.Println("ufw-docker-automated: Couldn't inspect container:", err)
						continue
					}
					createChannel <- &container
				}
				if msg.Action == "die" {
					deleteChannel <- msg.ID[:12]
				}
			}
		case err := <-errors:
			if err != nil {
				log.Println("ufw-docker-automated: Event error:", err)
				ctx, client, err = reconnect()
				messages, errors = streamEvents(ctx, client)
			}
		}
	}
}
