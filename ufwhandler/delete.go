package ufwhandler

import (
	"bytes"
	"log"
	"os/exec"

	"github.com/patrickmn/go-cache"
)

func DeleteUfwRule(containerID <-chan string, c *cache.Cache) {
	for id := range containerID {

		if cachedContainer, found := c.Get(id); found {
			container := cachedContainer.(*TrackedContainer)
			// Handle inbound rules
			for _, rule := range container.UfwInboundRules {
				cmd := exec.Command("sudo", "ufw", "route", "delete", "allow", "proto", rule.Proto, "from", rule.CIDR, "to", container.IPAddress, "port", rule.Port, "comment", container.Name+":"+id+rule.Comment)
				log.Println("ufw-docker-automated: Deleting rule:", cmd)

				var stdout, stderr bytes.Buffer
				cmd.Stdout = &stdout
				cmd.Stderr = &stderr
				err := cmd.Run()

				if err != nil || stderr.String() != "" {
					log.Println("ufw error:", err, stderr.String())
				} else {
					log.Println("ufw:", stdout.String())
				}
			}
			// Handle outbound rules
			for _, rule := range container.UfwOutboundRules {
				var cmd *exec.Cmd
				if rule.Port == "" {
					cmd = exec.Command("sudo", "ufw", "route", "delete", "allow", "from", container.IPAddress, "to", rule.CIDR, "comment", container.Name+":"+id+rule.Comment)
				} else {
					cmd = exec.Command("sudo", "ufw", "route", "delete", "allow", "from", container.IPAddress, "to", rule.CIDR, "port", rule.Port, "comment", container.Name+":"+id+rule.Comment)
				}
				log.Println("ufw-docker-automated: Deleting rule:", cmd)

				var stdout, stderr bytes.Buffer
				cmd.Stdout = &stdout
				cmd.Stderr = &stderr
				err := cmd.Run()

				if err != nil || stderr.String() != "" {
					log.Println("ufw error:", err, stderr.String())
				} else {
					log.Println("ufw:", stdout.String())
				}
			}
			// Handle deny all out
			cmd := exec.Command("sudo", "ufw", "route", "delete", "deny", "from", container.IPAddress, "to", "any", "comment", container.Name+":"+id)
			log.Println("ufw-docker-automated: Deleting rule:", cmd)

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			err := cmd.Run()

			if err != nil || stderr.String() != "" {
				log.Println("ufw error:", err, stderr.String())
			} else {
				log.Println("ufw:", stdout.String())
			}
		} else {
			log.Println("ufw-docker-automated: Container information not found")
			continue
		}
	}
}
