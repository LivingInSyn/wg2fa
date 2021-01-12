package main

import (
	"net/http"

	"./wireguard"

	"github.com/gorilla/mux"
)

// NewUser accepts POSTs of new user objects and creates a new wireguard user
func NewUser(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	wireguard.CreateNewUser()
}

// TotpTFA accepts POSTs of totp auth objects and adjusts users routing table if
// it is valid
func TotpTFA(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/newuser", NewUser).Methods("POST")
	r.HandleFunc("/totp", TotpTFA).Methods("POST")
	http.Handle("/", r)
}
