package wireguard

import (
	"path/filepath"
	"testing"
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
