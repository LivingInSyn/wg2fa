package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"./okta"
	"./wireguard"

	"github.com/gorilla/mux"
)

var wgclient wireguard.WGClient

// NewUser accepts POSTs of new user objects and creates a new wireguard user.
// The returned wireguard config will require the caller to replace CLIENT_PRIVATE_KEY
// with their private key
func NewUser(w http.ResponseWriter, r *http.Request) {
	if !okta.IsAuthenticated(r) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
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

// HomeHandler just returns a 200 OK
func HomeHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {
	// initialize the wireguard client
	// TODO: make these come from a conf file and
	// from flags
	wgclient = wireguard.WGClient{
		WGConfigPath:     "/etc/wireguard/wg0.conf",
		ClientConfigPath: "/etc/wireguard/clientConfigs",
		ClientListPath:   "/etc/wireguard/clientList",
		DNSServers:       []string{"8.8.8.8, 8.8.4.4"},
	}
	err := wgclient.Init()
	if err != nil {
		log.Fatal(err)
	}
	r := mux.NewRouter()
	r.HandleFunc("/", HomeHandler).Methods("GET")
	r.HandleFunc("/newuser", NewUser).Methods("POST")
	// okta functions
	r.HandleFunc("/login", okta.LoginHandler)
	r.HandleFunc("/authorization-code/callback", okta.AuthCodeCallbackHandler)
	r.HandleFunc("/logout", okta.LogoutHandler)
	// start
	http.Handle("/", r)
}

func generateNonce() (string, error) {
	nonceBytes := make([]byte, 32)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		return "", fmt.Errorf("could not generate nonce")
	}

	return base64.URLEncoding.EncodeToString(nonceBytes), nil
}
