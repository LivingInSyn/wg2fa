package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"./wireguard"

	"github.com/gorilla/mux"
)

var wgclient wireguard.WGClient
var state = "ApplicationState"
var nonce = "NonceNotSetYet"

// NewUser accepts POSTs of new user objects and creates a new wireguard user.
// The returned wireguard config will require the caller to replace CLIENT_PRIVATE_KEY
// with their private key
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

// LoginHandler handles the redirect to our oAuth2 provider to get a token
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	nonce, err := generateNonce()
	if err != nil {
		// TODO: log
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	var redirectPath string

	q := r.URL.Query()
	q.Add("client_id", os.Getenv("CLIENT_ID"))
	q.Add("response_type", "code")
	q.Add("response_mode", "query")
	q.Add("scope", "openid profile email")
	q.Add("redirect_uri", "http://localhost:8080/authorization-code/callback")
	q.Add("state", state)
	q.Add("nonce", nonce)

	redirectPath = os.Getenv("ISSUER") + "/v1/authorize?" + q.Encode()

	http.Redirect(w, r, redirectPath, http.StatusMovedPermanently)
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
	r.HandleFunc("/newuser", NewUser).Methods("POST")
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
