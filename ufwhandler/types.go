package ufwhandler

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
