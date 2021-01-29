package wireguard

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
)

const usernameRegex = "^[a-zAZ0-9\\.@_-]+$"
const sectionRegex = "^\\[[a-zA-Z0-9]+\\]$"

var serverPubKey string

// WGClient is a struct defining the config of wireguard
type WGClient struct {
	// WGConfigPath is the path to the wireguard config to manage
	WGConfigPath string
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
	PublicKey  string `json:"public_key"`
	WGConf     string `json:"wg_conf"`
}

// Init initializes a WGClient
func (c WGClient) Init() error {
	log.Debug().Msg("Initializing wireguard client")
	err := checkClientDb(c.ClientListPath, true)
	if err != nil {
		return err
	}
	// TODO: if keypath, check that the folder exists with sane permissions
	// TODO: if clientconfigpath check that the folder exists with sane permissions
	// TODO: check DNSServers for sanity. Len > 0 and proper IPs
	if c.ServerHostname == "" || !strings.Contains(c.ServerHostname, ":") {
		return errors.New("Invalid server hostname string")
	}
	// get and set the server public key
	wgConfig, err := parseConfig(c.WGConfigPath)
	if err != nil {
		return err
	}
	serverPrivkey := ""
	for _, configSection := range wgConfig {
		if configSection.SectionName == "Interface" {
			serverPrivkey = configSection.ConfigValues["PrivateKey"]
			break
		}
	}
	if serverPrivkey == "" {
		return errors.New("No server private key found")
	}
	serverPubKey, err = getPubKey(serverPrivkey)
	if err != nil {
		return err
	}
	return nil
}

// NewUser creates a new user
func (c WGClient) NewUser(newuser NewUser) (NewUser, error) {
	// check the username for regex
	match, err := regexp.MatchString(usernameRegex, newuser.ClientName)
	if err != nil {
		log.Error().Msg("Error in new user regex")
		return NewUser{}, errors.New("Error in new user regex")
	}
	if !match {
		return NewUser{}, errors.New("invalid username")
	}
	// get a PSK
	psk, err := createPSK()
	if err != nil {
		return NewUser{}, err
	}
	// find an unused IP
	ip, err := getOpenIP(c.WGConfigPath)
	if err != nil {
		return NewUser{}, err
	}
	// now build the config string:
	ccd := clientConfData{
		ClientIP:       ip,
		DNS:            strings.Join(c.DNSServers[:], ", "),
		ServerPubKey:   serverPubKey,
		PSK:            psk,
		ServerHostname: c.ServerHostname,
	}
	ccf, err := buildClientConfigFile(&ccd)
	if err != nil {
		return NewUser{}, err
	}
	// build the new users server config block and add it to the file
	sccd := serverCConfData{
		PublicKey: newuser.PublicKey,
		PSK:       psk,
		IP:        ip,
	}
	sccf, err := buildServerConfigBlock(&sccd)
	// todo: write sccf to the server config file
	err = addUserToSConf(c.WGConfigPath, sccf, &sccd)
	if err != nil {
		return NewUser{}, errors.New("Couldn't write to wg config file")
	}
	// finally, quick restart the wg server async
	// TODO: (is this REQUIRED??)

	// return the completed new user
	err = addClientToDb(newuser.ClientName, newuser.PublicKey, ip)
	if err != nil {
		return NewUser{}, err
	}
	// optionally write to the ClientConfigPath
	if c.ClientConfigPath != "" {
		keyfilename := fmt.Sprintf("%s/%s.conf", c.ClientConfigPath, newuser.ClientName)
		err = ioutil.WriteFile(keyfilename, []byte(ccf), 0644)
		if err != nil {
			log.Error().Str("error", err.Error()).Msg("error writing client conf")
		}
	}
	newuser.WGConf = ccf
	return newuser, nil
}

// RemoveUser deletes a user
func (c WGClient) RemoveUser(pubkey string) error {
	//remove from the wgconfig
	//remove from the clientlist
	removeClientFromDb(pubkey)
	return nil
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

func addUserToSConf(path, scb string, scd *serverCConfData) error {
	// check for dup public keys and error on presence
	confSections, err := parseConfig(path)
	if err != nil {
		return err
	}
	for _, sec := range confSections {
		// check if it's a peer:
		if strings.ToLower(sec.SectionName) == "peer" {
			//check the pubkey
			pubkey, ok := sec.ConfigValues["PublicKey"]
			if ok {
				if pubkey == *&scd.PublicKey {
					return errors.New("peer with that public key already exists")
				}
			} else {
				log.Warn().Msg("peer exists with no public key")
			}
		}
	}
	// add user to it by reading the file
	f, err := os.OpenFile(path,
		os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Error().AnErr("error opening server config file for writing", err)
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(scb); err != nil {
		log.Error().AnErr("error writing to server config file", err)
		return err
	}
	return nil
}

func getOpenIP(confPath string) (string, error) {
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
	currentClients, err := getClients()
	currentIPs := make(map[string]bool)
	for _, client := range currentClients {
		currentIPs[client.IP] = true
	}
	//add the server IP, too
	currentIPs[ip.String()] = true
	// for nip := ip.Mask(ipNet.Mask); ipNet.Contains(nip); inc(nip) {
	for nip := ip; ipNet.Contains(nip); inc(nip) {
		if currentIPs[nip.String()] == false {
			cidr := strings.Split(ipRangeString, "/")[1]
			return fmt.Sprintf("%s/%s", nip.String(), cidr), nil
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
