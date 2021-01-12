package wireguard

import (
	"errors"
	"log"
	"regexp"
)

const usernameRegex = "^[a-zAZ0-9\\.@_-]+$"

// WGClient is a struct defining the config of wireguard
type WGClient struct {
	// WGConfigPath is the path to the wireguard config to manage
	WGConfigPath string
	// KeyPath is the location of generated private keys for users
	KeyPath string
	// ClientConfigs is the location to write generated client configs to. If nil or blank this will not be written to disk
	ClientConfigPath string
}

// NewUser is the struct for a new wireguard user
// right now this only accepts ClientName and builds everything else
type NewUser struct {
	ClientName string `json:"client_name"`
	WGConf     string `json:"wg_conf"`
}

// Init initializes a WGClient
func (c WGClient) Init() error {
	return nil
}

// NewUser creates a new user
func (c WGClient) NewUser(newuser NewUser) (NewUser, error) {
	// check the username for regex
	match, err := regexp.MatchString(usernameRegex, newuser.ClientName)
	if err != nil {
		log.Fatal("Error in regex")
	}
	if !match {
		return NewUser{}, errors.New("invalid username")
	}
	// call to system to create a new user

	return newuser, nil
}
