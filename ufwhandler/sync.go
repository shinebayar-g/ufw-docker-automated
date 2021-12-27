package ufwhandler

import (
	"context"
	"log"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

func Sync(createChannel chan *types.ContainerJSON, client *client.Client, ctx *context.Context) {
	var filter = filters.NewArgs()
	filter.Add("label", "UFW_MANAGED=TRUE")
	containers, err := client.ContainerList(*ctx, types.ContainerListOptions{Filters: filter})
	if err != nil {
		log.Println(err)
	}

	for _, c := range containers {
		container, err := client.ContainerInspect(*ctx, c.ID)
		if err != nil {
			log.Println("ufw-docker-automated: Couldn't inspect container:", err)
			continue
		}
		createChannel <- &container
	}
}
