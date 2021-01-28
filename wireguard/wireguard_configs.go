package wireguard

import (
	"bufio"
	"database/sql"
	"errors"
	"os"
	"regexp"
	"strings"

	//the following is the go-sqlite driver
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
)

var db *sql.DB

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

func getClients() ([]clientConfig, error) {
	clients := make([]clientConfig, 0)
	rows, err := db.Query("select name, public_key, ip from wg_user")
	if err != nil {
		log.Error().AnErr("error selecting from sqlite", err)
		return clients, errors.New("error selecting from sqlite")
	}
	defer rows.Close()
	for rows.Next() {
		var cf clientConfig
		err = rows.Scan(&cf.Name, &cf.PublicKey, &cf.IP)
		if err != nil {
			log.Error().AnErr("error scanning row", err)
			return clients, errors.New("error selecting from sqlite")
		}
		clients = append(clients, cf)
	}
	err = rows.Err()
	if err != nil {
		log.Error().AnErr("rows err", err)
		return clients, errors.New("error selecting from sqlite")
	}
	return clients, nil
}

func addUserToClientList(name, pubkey, ip string) error {
	insertStmt := "INSERT INTO wg_user (public_key, name, ip) VALUES ($1, $2, $3);"
	_, err := db.Exec(insertStmt, pubkey, name, ip)
	if err != nil {
		log.Error().AnErr("error inserting into client table", err)
		return err
	}
	return nil
}

func checkClientConfig(confPath string, create bool) error {
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
		createStmt := "CREATE TABLE wg_user (public_key text not null primary key, name text, ip text);"
		_, err = db.Exec(createStmt)
		if err != nil {
			return err
		}
	}
	return nil
}

func closeWgConfig() {
	err := db.Close()
	if err != nil {
		log.Error().AnErr("error closing WG config DB", err)
	}
}
