package main

import (
	"time"

	"./wireguard"
	"github.com/rs/zerolog/log"
)

type removeClientConfig struct {
	// ForceTime is the number of minutes since authentication to force
	// reauthentication. If <= 0 this is ignored
	ForceTime int64
	// The number of minutes for a user to be idle before forcing a new auth. If
	// <= this is ignored
	IdleTime int64
}

func watchdog(wgc *wireguard.WGClient, rc *removeClientConfig) {
	for {
		time.Sleep(30 * time.Second)
		// get all the users
		clients, err := wireguard.GetClients()
		if err != nil {
			log.Error().AnErr("error getting clients from DB", err)
			continue
		}
		// get last handshakes
		lastHandshakes, err := wgc.GetLastHandshakes()
		if err != nil {
			log.Error().AnErr("Error getting last handshakes", err)
			continue
		}
		for _, client := range clients {
			if rc.ForceTime > 0 {
				minAgo := time.Now().Add(-1 * time.Duration(rc.ForceTime))
				if client.Added.Before(minAgo) {
					wgc.RemoveUser(client.PublicKey)
					continue
				}
			}
			if rc.IdleTime > 0 {
				lastHandshake := lastHandshakes[client.PublicKey]
				minAgo := time.Now().Add(-1 * time.Duration(rc.IdleTime))
				if lastHandshake.Before(minAgo) {
					wgc.RemoveUser(client.PublicKey)
				}
			}
		}
	}

}
