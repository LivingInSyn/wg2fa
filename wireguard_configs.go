package main

import (
	"bufio"
	"bytes"
	"database/sql"
	"errors"
	"html/template"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	//the following is the go-sqlite driver
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
)

var db *sql.DB
var clientTemplatePath = filepath.Join(".", "text_templates", "client_config.txt")
var serverTemplatePath = filepath.Join(".", "text_templates", "cserver_client_entry.txt")

// configSection is a configuration file ini section
type configSection struct {
	SectionName  string
	ConfigValues map[string]string
}

type clientConfData struct {
	ClientIP       string
	DNS            string
	ServerPubKey   string
	PSK            string
	ServerHostname string
}

type serverCConfData struct {
	PublicKey string
	PSK       string
	IP        string
	Interface string
}

// ClientConfig is an entry in the list of clients
type ClientConfig struct {
	Name      string    `json:"name"`
	PublicKey string    `json:"public_key"`
	IP        string    `json:"ip"`
	Added     time.Time `json:"added"`
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
	sections := make([]configSection, 0)
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
			log.Fatal().Msg("Error in regex while parsing wireguard config")
		}
		if match {
			// append the current and start a new
			sections = append(sections, currentSection)
			currentSection = newConfigSection(strings.Trim(line, "[]"))
		}
		// otherwise, append KVPs to the current section
		splitline := strings.SplitN(line, "=", 2)
		if len(splitline) > 1 {
			key := strings.Trim(splitline[0], " ")
			value := strings.Trim(splitline[1], " ")
			currentSection.ConfigValues[key] = value
		}
	}
	sections = append(sections, currentSection)
	return sections, nil
}

// getClients returns a list of all users currently in the DB
func getClients() ([]ClientConfig, error) {
	clients := make([]ClientConfig, 0)
	rows, err := db.Query("select name, public_key, ip, added from wg_user")
	if err != nil {
		log.Error().AnErr("error selecting from sqlite", err)
		return clients, errors.New("error selecting from sqlite")
	}
	defer rows.Close()
	for rows.Next() {
		var cf ClientConfig
		var timeString string
		err = rows.Scan(&cf.Name, &cf.PublicKey, &cf.IP, &timeString)
		if err != nil {
			log.Error().AnErr("error scanning row", err)
			return clients, errors.New("error selecting from sqlite")
		}
		//parse the time string and set it in cf
		uTime, err := time.Parse(time.RFC3339, timeString)
		if err != nil {
			log.Error().AnErr("error parsing added time, skipping user", err).Str("username", cf.Name)
			continue
		}
		cf.Added = uTime
		clients = append(clients, cf)
	}
	err = rows.Err()
	if err != nil {
		log.Error().AnErr("rows err", err)
		return clients, errors.New("error selecting from sqlite")
	}
	return clients, nil
}

func removeClientFromDb(pubKey string) error {
	delStmt := "DELETE FROM wg_user WHERE public_key = $1;"
	_, err := db.Exec(delStmt, pubKey)
	if err != nil {
		log.Error().AnErr("error deleting client", err)
		return errors.New("couldn't delete client")
	}
	return nil
}

func addClientToDb(name, pubkey, ip string) error {
	cTime := time.Now().Format(time.RFC3339)
	insertStmt := "INSERT INTO wg_user (public_key, name, ip, added) VALUES ($1, $2, $3, $4);"
	_, err := db.Exec(insertStmt, pubkey, name, ip, cTime)
	if err != nil {
		log.Error().AnErr("error inserting into client table", err)
		return err
	}
	return nil
}

func checkClientDb(confPath string, create bool) error {
	var err error
	db, err = sql.Open("sqlite3", confPath)
	if err != nil {
		return err
	}
	// check that the table exists and create it if 'create' is true
	tableExistStmt := "SELECT name FROM sqlite_master WHERE type='table' AND name='wg_user';"
	var tableName string
	err = db.QueryRow(tableExistStmt).Scan(&tableName)
	if err != nil {
		if !create {
			log.Error().Str("error", err.Error()).Msg("table doesn't exist and create is off")
			return errors.New("Invalid config file and create is off")
		}
		createStmt := "CREATE TABLE wg_user (public_key text not null primary key, name text, ip text, added text);"
		_, err = db.Exec(createStmt)
		if err != nil {
			return err
		}
	}
	return nil
}

func closeClientDb() {
	err := db.Close()
	if err != nil {
		log.Error().AnErr("error closing WG config DB", err)
	}
}

func buildClientConfigFile(ccd *clientConfData) (string, error) {
	//read the template into a file
	path := clientTemplatePath
	templText, err := ioutil.ReadFile(path)
	if err != nil {
		log.Error().AnErr("couldn't read client config", err)
		return "", err
	}
	// create a template
	tmpl, err := template.New("clientTempl").Parse(string(templText))
	if err != nil {
		log.Error().AnErr("couldn't template client config", err)
		return "", err
	}
	// execute it and read it into a string
	var tbuffer bytes.Buffer
	err = tmpl.Execute(&tbuffer, ccd)
	if err != nil {
		log.Error().AnErr("couldn't execute client template", err)
		return "", err
	}
	return tbuffer.String(), nil
}
