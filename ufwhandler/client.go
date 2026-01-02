package ufwhandler

import (
	"context"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/rs/zerolog/log"
)

func CreateClient() (*context.Context, *client.Client, error) {
	ctx := context.Background()
	client, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return &ctx, client, err
	}
	_, err = client.Info(ctx)
	return &ctx, client, err
}

func Reconnect() (*context.Context, *client.Client) {
	var ctx *context.Context
	var client *client.Client
	var err error
	for {
		time.Sleep(5 * time.Second)
		log.Info().Msg("ufw-docker-automated: Trying to reconnect..")
		ctx, client, err = CreateClient()
		if err == nil {
			break
		}
	}
	log.Info().Msg("ufw-docker-automated: Reconnected to the Docker Engine.")
	return ctx, client
}

func StreamEvents(ctx *context.Context, c *client.Client) (<-chan events.Message, <-chan error) {
	filter := filters.NewArgs()
	filter.Add("type", "container")
	filter.Add("label", "UFW_MANAGED=TRUE")
	return c.Events(*ctx, types.EventsOptions{Filters: filter})
}
