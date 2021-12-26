package ufwhandler

import (
	"bytes"
	"log"
	"os/exec"
)

func DeleteUfwRule(containerID <-chan string, trackedContainers map[string]*TrackedContainer) {
	for id := range containerID {

		if c, ok := trackedContainers[id]; ok {
			// Handle inbound rules
			for _, rule := range c.UfwInboundRules {
				cmd := exec.Command("sudo", "ufw", "route", "delete", "allow", "proto", rule.Proto, "from", rule.CIDR, "to", c.IPAddress, "port", rule.Port, "comment", c.Name+":"+id+rule.Comment)
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
			for _, rule := range c.UfwOutboundRules {
				var cmd *exec.Cmd
				if rule.Port == "" {
					cmd = exec.Command("sudo", "ufw", "route", "delete", "allow", "from", c.IPAddress, "to", rule.CIDR, "comment", c.Name+":"+id+rule.Comment)
				} else {
					cmd = exec.Command("sudo", "ufw", "route", "delete", "allow", "from", c.IPAddress, "to", rule.CIDR, "port", rule.Port, "comment", c.Name+":"+id+rule.Comment)
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
			cmd := exec.Command("sudo", "ufw", "route", "delete", "deny", "from", c.IPAddress, "to", "any", "comment", c.Name+":"+id)
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
