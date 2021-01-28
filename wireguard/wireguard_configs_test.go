package wireguard

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog/log"
)

func TestParseConfig(t *testing.T) {
	confpath := filepath.Join("..", "test", "wg0.conf")
	parsedConf, err := parseConfig(confpath)
	if err != nil {
		t.Errorf("error parsing wg0.conf")
		return
	}
	if len(parsedConf) == 0 {
		t.Errorf("returned empty config")
		return
	}
	for _, section := range parsedConf {
		if section.SectionName != "Interface" {
			continue
		}
		if section.ConfigValues["Address"] != "10.0.0.1/24" {
			t.Errorf("invalid server address")
		}
		if section.ConfigValues["ListenPort"] != "51820" {
			t.Errorf("invalid listen port")
		}
		expectedKey := "YF4YWG1+uqRJe1uRnn+/S4JPALCfHUxEgug+W+XvNEY="
		confKey := section.ConfigValues["PrivateKey"]
		if confKey != expectedKey {
			t.Errorf("invalid private key. \nGot %s\nexpected %s", confKey, expectedKey)
		}
	}
}

func TestCheckClientConfigCreate(t *testing.T) {
	confpath := filepath.Join("..", "test", "cc_create.db")
	err := checkClientConfig(confpath, true)
	if err != nil {
		t.Errorf("error creating checking/creating client config")
	}
	closeWgConfig()
	deleteFile(confpath)
}

func TestCheckClientConfigNoCreate(t *testing.T) {
	confpath := filepath.Join("..", "test", "no_create.db")
	err := checkClientConfig(confpath, false)
	if err == nil {
		t.Errorf("we should get an error here")
	}
	deleteFile(confpath)
}

func TestAddGetClients(t *testing.T) {
	confpath := filepath.Join("..", "test", "addgetclient.db")
	// call check/create to make sure we have a db
	err := checkClientConfig(confpath, true)
	if err != nil {
		t.Errorf("error creating checking/creating client config")
	}
	// add two users
	err = addUserToClientList("bob", "abc123", "192.168.1.1")
	if err != nil {
		t.Errorf("error adding first user")
	}
	err = addUserToClientList("tom", "abc456", "192.168.1.100")
	if err != nil {
		t.Errorf("error adding second user")
	}
	// get those users
	clients, err := getClients()
	if err != nil {
		t.Errorf("error getting clients")
	}
	if len(clients) != 2 {
		t.Errorf("wrong number of clients")
	}
	closeWgConfig()
	deleteFile(confpath)
}

func TestOpenIP(t *testing.T) {
	confpath := filepath.Join("..", "test", "addgetclient.db")
	// call check/create to make sure we have a db
	err := checkClientConfig(confpath, true)
	if err != nil {
		t.Errorf("error creating checking/creating client config")
	}
	// add two users
	err = addUserToClientList("bob", "abc123", "10.0.0.2")
	if err != nil {
		t.Errorf("error adding first user")
	}
	err = addUserToClientList("tom", "abc456", "10.0.0.200")
	if err != nil {
		t.Errorf("error adding second user")
	}
	// get the next open IP
	serverConfPath := filepath.Join("..", "test", "wg0.conf")
	ip, err := getOpenIP(serverConfPath)
	if err != nil {
		t.Errorf("error getting open IP")
	}
	if ip != "10.0.0.3/24" {
		t.Errorf("wrong IP returned")
	}
	closeWgConfig()
	deleteFile(confpath)
}

func deleteFile(path string) {
	err := os.Remove(path)
	if err != nil {
		log.Error().AnErr("couldn't delete test file", err)
	}
}
