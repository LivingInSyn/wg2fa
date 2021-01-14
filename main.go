package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"

	"./wireguard"

	"github.com/gorilla/mux"
)

var wgclient wireguard.WGClient

// NewUser accepts POSTs of new user objects and creates a new wireguard user
func NewUser(w http.ResponseWriter, r *http.Request) {
	reqbody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var newUser wireguard.NewUser
	err = json.Unmarshal(reqbody, &newUser)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	createdUser, err := wgclient.NewUser(newUser)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	jsonNewUser, err := json.Marshal(createdUser)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Write(jsonNewUser)
	w.WriteHeader(http.StatusOK)
}

// TotpTFA accepts POSTs of totp auth objects and adjusts users routing table if
// it is valid
func TotpTFA(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func main() {
	// initialize the wireguard client
	// TODO: make these come from a conf file and
	// from flags
	wgclient = wireguard.WGClient{
		WGConfigPath:     "/etc/wireguard/wg0.conf",
		KeyPath:          "/etc/wireguard/clientKeys",
		ClientConfigPath: "/etc/wireguard/clientConfigs",
		ClientListPath:   "/etc/wireguard/clientList",
		DNSServers:       []string{"8.8.8.8, 8.8.4.4"},
	}
	err := wgclient.Init()
	if err != nil {
		log.Fatal(err)
	}
	r := mux.NewRouter()
	r.HandleFunc("/newuser", NewUser).Methods("POST")
	r.HandleFunc("/totp", TotpTFA).Methods("POST")
	http.Handle("/", r)
}
