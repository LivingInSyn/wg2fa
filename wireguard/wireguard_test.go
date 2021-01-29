package wireguard

import (
	"os"
	"path/filepath"
	"strings"
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
	err := checkClientDb(confpath, true)
	if err != nil {
		t.Errorf("error creating checking/creating client config")
	}
	closeClientDb()
	deleteFile(confpath)
}

func TestCheckClientConfigNoCreate(t *testing.T) {
	confpath := filepath.Join("..", "test", "no_create.db")
	err := checkClientDb(confpath, false)
	if err == nil {
		t.Errorf("we should get an error here")
	}
	deleteFile(confpath)
}

func TestAddGetClients(t *testing.T) {
	confpath := filepath.Join("..", "test", "addgetclient.db")
	// call check/create to make sure we have a db
	err := checkClientDb(confpath, true)
	if err != nil {
		t.Errorf("error creating checking/creating client config")
	}
	// add two users
	err = addClientToDb("bob", "abc123", "192.168.1.1")
	if err != nil {
		t.Errorf("error adding first user")
	}
	err = addClientToDb("tom", "abc456", "192.168.1.100")
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
	closeClientDb()
	deleteFile(confpath)
}

func TestOpenIP(t *testing.T) {
	confpath := filepath.Join("..", "test", "addgetclient.db")
	// call check/create to make sure we have a db
	err := checkClientDb(confpath, true)
	if err != nil {
		t.Errorf("error creating checking/creating client config")
	}
	// add two users
	err = addClientToDb("bob", "abc123", "10.0.0.2")
	if err != nil {
		t.Errorf("error adding first user")
	}
	err = addClientToDb("tom", "abc456", "10.0.0.200")
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
	closeClientDb()
	deleteFile(confpath)
}

func TestBuildClientConfig(t *testing.T) {
	goodBlock := `[Interface]
PrivateKey = CLIENT_PRIVATE_KEY
Address = 10.0.0.5/24
DNS = 8.8.8.8, 8.8.4.4

[Peer]
PublicKey = abc123
PresharedKey = def456
Endpoint = example.com:12345
`
	clientTemplatePath = filepath.Join("..", "text_templates", "client_config.txt")
	ccd := clientConfData{
		ClientIP:       "10.0.0.5/24",
		DNS:            "8.8.8.8, 8.8.4.4",
		ServerPubKey:   "abc123",
		PSK:            "def456",
		ServerHostname: "example.com:12345",
	}
	ccf, err := buildClientConfigFile(&ccd)
	if err != nil {
		t.Errorf("failed to exec template: %s", err)
	}
	// just in case, replace CR with nothing
	ccf = strings.Replace(ccf, "\r", "", -1)
	if !strings.HasPrefix(ccf, goodBlock) {
		t.Logf("good: %s", goodBlock)
		t.Logf("bad: %s", ccf)
		t.Errorf("failed to match good block")
	}

}

func TestBuildServerClientBlock(t *testing.T) {
	goodBlock := `[Peer]
PublicKey = abc123
PresharedKey = def456
AllowedIPs = 10.0.0.5/24
`

	serverTemplatePath = filepath.Join("..", "text_templates", "server_client_entry.txt")
	sccd := serverCConfData{
		PublicKey: "abc123",
		PSK:       "def456",
		IP:        "10.0.0.5/24",
	}
	sccf, err := buildServerConfigBlock(&sccd)
	if err != nil {
		t.Errorf("failed to exec template: %s", err)
	}
	sccf = strings.Replace(sccf, "\r", "", -1)
	if !strings.HasPrefix(sccf, goodBlock) {
		// for i, c := range sccf {
		// 	t.Logf("%d %c %c", i, c, goodBlock[i])
		// }
		t.Logf("good: %s", goodBlock)
		t.Logf("bad: %s", sccf)
		t.Errorf("failed to match good block")
	}
}

func deleteFile(path string) {
	err := os.Remove(path)
	if err != nil {
		log.Error().AnErr("couldn't delete test file", err)
	}
}
