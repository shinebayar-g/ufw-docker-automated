package ufwhandler

import (
	"context"
	"log"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

func Sync(createChannel chan *types.ContainerJSON, client *client.Client, ctx *context.Context) {
	// Returns only running containers
	filter := filters.NewArgs()
	filter.Add("label", "UFW_MANAGED=TRUE")
	containers, err := client.ContainerList(*ctx, types.ContainerListOptions{Filters: filter})
	if err != nil {
		log.Println("ufw-docker-automated: Couldn't retrieve existing containers:", err)
	}

	for _, c := range containers {
		container, err := client.ContainerInspect(*ctx, c.ID)
		if err != nil {
			log.Println("ufw-docker-automated: Couldn't inspect existing container:", err)
			continue
		}
		createChannel <- &container
	}
}
