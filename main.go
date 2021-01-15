package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"

	"./wireguard"

	"github.com/gorilla/mux"
	jwtverifier "github.com/okta/okta-jwt-verifier-golang"
)

var wgclient wireguard.WGClient
var clientID = "0oawepftsdT43o2CM0h7"
var issuer = "https://dev-318981-admin.oktapreview.com/oauth2/default"

// NewUser accepts POSTs of new user objects and creates a new wireguard user.
// The returned wireguard config will require the caller to replace CLIENT_PRIVATE_KEY
// with their private key
func NewUser(w http.ResponseWriter, r *http.Request) {
	btoken := r.Header.Get("Bearer")
	if isAuthenticated(btoken) {
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
	// start
	http.Handle("/", r)
}

func isAuthenticated(jwt string) bool {
	toValidate := map[string]string{}
	toValidate["aud"] = "api://default"
	toValidate["cid"] = clientID

	jwtVerifierSetup := jwtverifier.JwtVerifier{
		Issuer:           issuer,
		ClaimsToValidate: toValidate,
	}

	verifier := jwtVerifierSetup.New()

	_, err := verifier.VerifyAccessToken(jwt)
	return err != nil
}
