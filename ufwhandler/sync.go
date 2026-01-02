package ufwhandler

import (
	"context"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/rs/zerolog/log"
)

func Sync(ctx *context.Context, createChannel chan *types.ContainerJSON, client *client.Client) {
	// Returns only running containers
	filter := filters.NewArgs()
	filter.Add("label", "UFW_MANAGED=TRUE")
	containers, err := client.ContainerList(*ctx, types.ContainerListOptions{Filters: filter})
	if err != nil {
		log.Error().Err(err).Msg("ufw-docker-automated: Couldn't retrieve existing containers.")
	}

	for _, c := range containers {
		container, err := client.ContainerInspect(*ctx, c.ID)
		if err != nil {
			log.Error().Err(err).Msg("ufw-docker-automated: Couldn't inspect existing container.")
			continue
		}
		createChannel <- &container
	}
}
