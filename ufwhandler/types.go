package ufwhandler

import (
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
)

type TrackedContainer struct {
	Name             string
	IPAddress        string
	Labels           map[string]string
	UfwInboundRules  []UfwRule
	UfwOutboundRules []UfwRule
}

type UfwRule struct {
	CIDR    string
	Port    string
	Proto   string
	Comment string
}

type UfwEvent struct {
	Container *types.ContainerJSON
	Msg       *events.Message
}
