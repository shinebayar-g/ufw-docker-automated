package main

import (
	"github.com/docker/docker/api/types"
	"github.com/patrickmn/go-cache"
	"github.com/rs/zerolog/log"
	"github.com/shinebayar-g/ufw-docker-automated/logger"
	"github.com/shinebayar-g/ufw-docker-automated/ufwhandler"
)

func main() {
	logger.SetupLogger()
	ctx, client, err := ufwhandler.CreateClient()
	if err != nil {
		log.Error().Err(err).Msg("ufw-docker-automated: Client error.")
		ctx, client = ufwhandler.Reconnect()
	} else {
		log.Info().Msg("ufw-docker-automated: Connected to the Docker Engine.")
	}
	createChannel := make(chan *types.ContainerJSON)
	deleteChannel := make(chan string)
	trackedContainers := cache.New(cache.NoExpiration, 0)

	go ufwhandler.CreateUfwRule(createChannel, trackedContainers)
	go ufwhandler.DeleteUfwRule(deleteChannel, trackedContainers)
	go ufwhandler.Cleanup(ctx, client)
	go ufwhandler.Sync(ctx, createChannel, client)

	messages, errors := ufwhandler.StreamEvents(ctx, client)
	for {
		select {
		case msg := <-messages:
			if msg.Action == "start" {
				container, err := client.ContainerInspect(*ctx, msg.ID)
				if err != nil {
					log.Error().Err(err).Msg("ufw-docker-automated: Couldn't inspect container.")
					continue
				}
				createChannel <- &container
			}
			if msg.Action == "die" {
				deleteChannel <- msg.ID[:12]
			}
		case err := <-errors:
			if err != nil {
				log.Error().Err(err).Msg("ufw-docker-automated: Event error.")
				ctx, client = ufwhandler.Reconnect()
				go ufwhandler.Sync(ctx, createChannel, client)
				messages, errors = ufwhandler.StreamEvents(ctx, client)
			}
		}
	}
}
