package wireguard

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
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
	// ClientListPath is the location of the file that stores the list of configured clients, their IP and public key. No private data
	ClientListPath string
	// DNS is a slice of strings for what DNS servers to configure
	DNSServers []string
	// ServerHostname is the hostname or IP of the server in host:port format
	ServerHostname string
}

// NewUser is the struct for a new wireguard user
// right now this only accepts ClientName and builds everything else
type NewUser struct {
	ClientName string `json:"client_name"`
	WGConf     string `json:"wg_conf"`
}

// Init initializes a WGClient
func (c WGClient) Init() error {
	// TODO: make sure that the client config file exists and is formatted
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
	// get the current wireguard config
	wgConfig, err := parseConfig(c.WGConfigPath)
	if err != nil {
		return NewUser{}, err
	}
	// get the public key:
	serverPrivkey := ""
	for _, configSection := range wgConfig {
		if configSection.SectionName == "Interface" {
			serverPrivkey = configSection.ConfigValues["PrivateKey"]
			break
		}
	}
	if serverPrivkey == "" {
		return NewUser{}, errors.New("No server private key found")
	}
	serverPubKey, err := getPubKey(serverPrivkey)
	if err != nil {
		return NewUser{}, err
	}
	// call to system to create a new user
	// generate keys:
	privkey, pubkey, err := createWGKey()
	if err != nil {
		return NewUser{}, err
	}
	_ = pubkey
	// get a PSK
	psk, err := createPSK()
	if err != nil {
		return NewUser{}, err
	}
	// find an unused IP
	ip, err := getOpenIP(c.WGConfigPath, c.ClientConfigPath)
	if err != nil {
		return NewUser{}, err
	}
	// now build the config string:
	// TODO: make this NOT gross (should be a file template)
	ccf := ""
	ccf = ccf + "[Interface]\n"
	ccf = ccf + fmt.Sprintf("PrivateKey = %s\n", privkey)
	ccf = ccf + fmt.Sprintf("Address = %s\n", ip)
	ccf = ccf + fmt.Sprintf("DNS = %s\n", strings.Join(c.DNSServers[:], ", "))
	ccf = ccf + "\n"
	ccf = ccf + "[Peer]\n"
	ccf = ccf + fmt.Sprintf("PublicKey = %s\n", serverPubKey)
	ccf = ccf + fmt.Sprintf("PresharedKey = %s\n", psk)
	ccf = ccf + fmt.Sprintf("Endpoint = %s\n", c.ServerHostname)
	// TODO: change this since that's like... the whole point of this project
	ccf = ccf + fmt.Sprintf("AllowedIPs = %s\n", "0.0.0.0/0, ::0/0")
	// return the completed new user
	addUserToClientConfig(c.ClientConfigPath, newuser.ClientName, pubkey, ip)
	newuser.WGConf = ccf
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
	pubkey, err := getPubKey(privkey)
	if err != nil {
		return "", "", err
	}
	return privkey, pubkey, nil
}

func getPubKey(privkey string) (string, error) {
	// generate a public key using privkey as input on stdin
	cmd := exec.Command("wg", "pubkey")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", err
	}
	go func() {
		defer stdin.Close()
		io.WriteString(stdin, privkey)
	}()
	pubkeyBytes, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	pubkey := string(pubkeyBytes)
	return pubkey, nil
}

func createPSK() (string, error) {
	pskBytes, err := exec.Command("wg", "genpsk").Output()
	if err != nil {
		return "", err
	}
	psk := string(pskBytes)
	return psk, nil
}

func getOpenIP(confPath, clientConfPath string) (string, error) {
	// get the current config and the server IP range:
	wgConfig, err := parseConfig(confPath)
	if err != nil {
		return "", nil
	}
	ipRangeString := ""
	for _, section := range wgConfig {
		if section.SectionName == "Interface" {
			ipRangeString = section.ConfigValues["Address"]
			break
		}
	}
	if ipRangeString == "" {
		return "", errors.New("No IP Range string found")
	}
	ip, ipNet, err := net.ParseCIDR(ipRangeString)
	currentClients, err := parseClientConfig(clientConfPath)
	currentIPs := make(map[string]bool)
	for _, client := range currentClients.Clients {
		currentIPs[client.IP] = true
	}
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		if currentIPs[ip.String()] == false {
			cidr := strings.Split(ipRangeString, "/")[1]
			return fmt.Sprintf("%s/%s", ip.String(), cidr), nil
		}
	}
	return "", errors.New("IP Space exhausted")
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
