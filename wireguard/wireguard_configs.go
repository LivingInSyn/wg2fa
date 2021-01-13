package wireguard

import (
	"bufio"
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strings"
)

// configSection is a configuration file ini section
type configSection struct {
	SectionName  string
	ConfigValues map[string]string
}

// ClientConfig is an entry in the list of clients
type clientConfig struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	IP        string `json:"ip"`
}

// Clients is the struct of clientConfigs
type Clients struct {
	Clients []clientConfig `json:"clients"`
}

// newconfigSection returns a new configSection with the name initialized
func newConfigSection(name string) configSection {
	return configSection{
		SectionName:  name,
		ConfigValues: make(map[string]string),
	}
}

func parseConfig(confPath string) ([]configSection, error) {
	// open the file
	confFile, err := os.Open(confPath)
	if err != nil {
		return nil, err
	}
	defer confFile.Close()
	// scan it breaking it down into sections
	sections := make([]configSection, 10)
	currentSection := newConfigSection("Default")
	scanner := bufio.NewScanner(confFile)
	for scanner.Scan() {
		line := scanner.Text()
		// skip comments
		if strings.HasPrefix(line, "#") {
			continue
		}
		// check if we're starting a new section
		match, err := regexp.MatchString(sectionRegex, line)
		if err != nil {
			log.Fatal("Error in regex")
		}
		if match {
			// append the current and start a new
			sections = append(sections, currentSection)
			currentSection = newConfigSection(strings.Trim(line, "[]"))
		}
		// otherwise, append KVPs to the current section
		splitline := strings.Split(line, "=")
		key := strings.Trim(splitline[0], " ")
		value := strings.Trim(splitline[1], " ")
		currentSection.ConfigValues[key] = value
	}
	sections = append(sections, currentSection)
	return sections, nil
}

func parseClientConfig(confPath string) (Clients, error) {
	jsonFile, err := os.Open("confPath")
	if err != nil {
		return Clients{}, err
	}
	defer jsonFile.Close()
	confBytes, _ := ioutil.ReadAll(jsonFile)
	var allClients Clients
	json.Unmarshal(confBytes, &allClients)
	return allClients, nil
}

func addUserToClientConfig(confPath, name, pubkey, ip string) error {
	//get the current config
	clientConf, err := parseClientConfig(confPath)
	if err != nil {
		return err
	}
	newclient := clientConfig{
		Name:      name,
		PublicKey: pubkey,
		IP:        ip,
	}
	clientConf.Clients = append(clientConf.Clients, newclient)
	//json dump the clientConf and write it to a file
	newConf, err := json.Marshal(clientConf)
	if err != nil {
		return err
	}
	confFile, err := os.Open(confPath)
	if err != nil {
		return err
	}
	defer confFile.Close()
	//clear the old
	err = confFile.Truncate(0)
	if err != nil {
		return err
	}
	//write the new
	_, err = confFile.Write(newConf)
	if err != nil {
		return err
	}
	return nil
}
