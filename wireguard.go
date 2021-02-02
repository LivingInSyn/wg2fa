package main

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

const usernameRegex = "^[a-zAZ0-9\\.@_-]+$"
const sectionRegex = "^\\[[a-zA-Z0-9]+\\]$"

var serverPubKey string

// WGClient is a struct defining the config of wireguard
type WGClient struct {
	// WGConfigPath is the path to the wireguard config to manage
	WGConfigPath string
	// InterfaceName is the name of the interface (wg0, etc.)
	InterfaceName string
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
func (c WGClient) init() error {
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
	if c.InterfaceName == "" {
		// TODO: more robust check of interface name here
		return errors.New("invalid interface name")
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
func (c WGClient) newUser(newuser NewUser) (NewUser, error) {
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
		Interface: c.InterfaceName,
	}
	// add user to config file
	err = addUserToSConf(&sccd)
	if err != nil {
		return NewUser{}, errors.New("Couldn't write to client to wg config")
	}
	// return the completed new user
	err = addClientToDb(newuser.ClientName, newuser.PublicKey, ip)
	if err != nil {
		return NewUser{}, err
	}
	newuser.WGConf = ccf
	return newuser, nil
}

// RemoveUser deletes a user
func (c WGClient) removeUser(pubkey string) error {
	//remove from the wgconfig
	commandArgs := []string{"set", c.InterfaceName, "peer", pubkey, "remove"}
	err := exec.Command("wg", commandArgs...).Wait()
	if err != nil {
		log.Error().AnErr("error adding peer to wg config", err)
		return err
	}
	//remove from the clientlist
	if err = removeClientFromDb(pubkey); err != nil {
		return err
	}
	return nil
}

// GetLastHandshakes returns a map of public keys to last handshake times
func (c WGClient) getLastHandshakes() (map[string]time.Time, error) {
	handshakes := make(map[string]time.Time)
	args := []string{"show", c.InterfaceName, "latest-handshakes"}
	hsbytes, err := exec.Command("wg", args...).Output()
	if err != nil {
		log.Error().AnErr("error calling latest handshakes", err)
		return handshakes, err
	}
	hsOut := string(hsbytes)
	lines := strings.Split(hsOut, "\n")
	for _, line := range lines {
		splitline := strings.Split(line, " ")
		pubkey := splitline[0]
		if len(pubkey) < 5 {
			log.Warn().Msg("invalid public key")
		}
		timeint, err := strconv.ParseInt(splitline[len(splitline)-1], 10, 64)
		if err != nil {
			log.Error().AnErr("error converting last handshake to int", err).Str("pubkey", pubkey)
			continue
		}
		tm := time.Unix(timeint, 0)
		handshakes[pubkey] = tm
	}
	return handshakes, nil
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

func addUserToSConf(scd *serverCConfData) error {
	// we need to write PSK to a temp file
	tmpFile, err := ioutil.TempFile(os.TempDir(), "wg2fa-")
	if err != nil {
		log.Error().AnErr("Cannot create temporary file", err)
		return err
	}
	// Remember to clean up the file afterwards
	defer os.Remove(tmpFile.Name())
	if _, err = tmpFile.Write([]byte(scd.PSK)); err != nil {
		log.Error().AnErr("Failed to write to temporary file", err)
		return err
	}
	// close it
	if err := tmpFile.Close(); err != nil {
		log.Error().AnErr("error closing temp file", err)
		return err
	}
	commandArgs := []string{"set", scd.Interface, "peer", scd.PublicKey, "preshared-key", tmpFile.Name(), "allowed-ips", scd.IP}
	// for some reason .Wait caused a crash here, so changing to output and logging it works :shrug:
	obytes, err := exec.Command("/usr/bin/wg", commandArgs...).Output()
	log.Debug().Str("command out", string(obytes))
	if err != nil {
		log.Error().AnErr("error adding peer to wg config", err).Msg("Error calling wg set")
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
