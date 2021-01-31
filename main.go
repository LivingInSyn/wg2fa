package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"net/http"
	"time"

	"./wireguard"

	"github.com/gorilla/mux"
	jwtverifier "github.com/okta/okta-jwt-verifier-golang"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var wgclient wireguard.WGClient
var clientID = "0oawepftsdT43o2CM0h7"
var issuer = "https://dev-318981-admin.oktapreview.com/oauth2/default"
var disableAuth = false

// NewUser accepts POSTs of new user objects and creates a new wireguard user.
// The returned wireguard config will require the caller to replace CLIENT_PRIVATE_KEY
// with their private key
func NewUser(w http.ResponseWriter, r *http.Request) {
	btoken := r.Header.Get("Bearer")
	if !disableAuth && isAuthenticated(btoken) {
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
		log.Error().Str("error", err.Error()).Msg("Error creating new user")
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
	debugFlag := flag.Bool("debug", false, "turn debug logging on")
	turnOffAuthFlag := flag.Bool("dangerauth", false, "turn on to disable auth to the newuser API")
	wgConfPathFlag := flag.String("wgc", "/etc/wireguard/wg0.conf", "the path to the wireguard config managed by wg2fa")
	wgClientListPathFlag := flag.String("cl", "/etc/wireguard/clientList", "the path to write the clientList to")
	ForceTimeFlag := flag.Int64("f", -1, "The number of minutes since auth to force a reauth regardless of activity")
	IdleTimeFlag := flag.Int64("i", 10, "The number of minutes since last activity to force a reauth")
	//TODO:
	// ForceRecreateFlag := flag.Bool("force-recreate", false, "force the recreation of the user database and clearing all authenticated users")
	flag.Parse()
	// setup logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	if *debugFlag {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
	// if we want auth to be disables for testing:
	if *turnOffAuthFlag {
		disableAuth = true
	}
	// initialize the wireguard client
	// TODO: make these come from a conf file and
	// from flags
	wgclient = wireguard.WGClient{
		WGConfigPath:   *wgConfPathFlag,
		ClientListPath: *wgClientListPathFlag,
		DNSServers:     []string{"8.8.8.8, 8.8.4.4"},
		ServerHostname: "localhost:51280",
		InterfaceName:  "wg0",
	}
	err := wgclient.Init()
	if err != nil {
		log.Fatal().Msg(err.Error())
	}
	// start the watchdog timer
	rcc := removeClientConfig{
		ForceTime: *ForceTimeFlag,
		IdleTime:  *IdleTimeFlag,
	}
	go watchdog(&wgclient, &rcc)
	// start the router
	r := mux.NewRouter()
	r.HandleFunc("/", HomeHandler).Methods("GET")
	r.HandleFunc("/newuser", NewUser).Methods("POST")
	// start
	srv := &http.Server{
		Addr: "0.0.0.0:8080",
		// Good practice to set timeouts to avoid Slowloris attacks.
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      r, // Pass our instance of gorilla/mux in.
	}
	log.Fatal().Msg(srv.ListenAndServe().Error())
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
