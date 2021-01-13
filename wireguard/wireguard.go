package wireguard

import (
	"bufio"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

const usernameRegex = "^[a-zAZ0-9\\.@_-]+$"
const sectionRegex = "^\\[[a-zA-Z0-9]+\\]$"

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
	// generate keys:
	privkey, pubkey, err := createWGKey()
	if err != nil {
		return NewUser{}, err
	}
	_ = privkey
	_ = pubkey
	// get a PSK
	psk, err := createPSK()
	if err != nil {
		return NewUser{}, err
	}
	_ = psk
	// find an unused IP

	return newuser, nil
}

func createWGKey() (string, string, error) {
	// create a new private key
	privkeyBytes, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		return "", "", err
	}
	privkey := string(privkeyBytes)
	// generate a public key using privkey as input on stdin
	cmd := exec.Command("wg", "pubkey")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", "", err
	}
	go func() {
		defer stdin.Close()
		io.WriteString(stdin, privkey)
	}()
	pubkeyBytes, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", err
	}
	pubkey := string(pubkeyBytes)
	return privkey, pubkey, nil
}

func createPSK() (string, error) {
	pskBytes, err := exec.Command("wg", "genpsk").Output()
	if err != nil {
		return "", err
	}
	psk := string(pskBytes)
	return psk, nil
}

// ConfigSection is a configuration file ini section
type ConfigSection struct {
	SectionName  string
	ConfigValues map[string]string
}

// NewConfigSection returns a new ConfigSection with the name initialized
func NewConfigSection(name string) ConfigSection {
	return ConfigSection{
		SectionName:  name,
		ConfigValues: make(map[string]string),
	}
}

func parseConfig(confPath string) {
	// open the file
	confFile, err := os.Open(confPath)
	if err != nil {
		log.Fatal(err)
	}
	defer confFile.Close()
	// scan it breaking it down into sections
	sections := make([]ConfigSection, 10)
	currentSection := NewConfigSection("Default")
	scanner := bufio.NewScanner(confFile)
	for scanner.Scan() {
		line := scanner.Text()
		// check if we're starting a new section
		match, err := regexp.MatchString(sectionRegex, line)
		if err != nil {
			log.Fatal("Error in regex")
		}
		if match {
			// append the current and start a new
			sections = append(sections, currentSection)
			currentSection = NewConfigSection(strings.Trim(line, "[]"))
		}
		// otherwise, append KVPs to the current section
		splitline := strings.Split(line, "=")
		key := strings.Trim(splitline[0], " ")
		value := strings.Trim(splitline[1], " ")
		currentSection.ConfigValues[key] = value
	}
}

func getOpenIP(confPath string) (string, error) {
	// read the config file to get the server subnet
	confFile, err := os.Open(confPath)
	if err != nil {
		log.Fatal(err)
	}
	defer confFile.Close()

	scanner := bufio.NewScanner(confFile)
	ipRangeString := ""
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Address") {
			splitlines := strings.Split(line, "=")
			ipRangeString = strings.Trim(splitlines[1], " ")
			break
		}
	}
	severIPAddr, ipNet, err := net.ParseCIDR(ipRangeString)
	if err != nil {
		return "", nil
	}
	// TODO: go up the range of clients and
	return "", nil
}

// TODO: rethink this. I think one pass parsing the whole wireguard config is going
// to be a better option than what I'm doing in this disaster of getOpenIP
