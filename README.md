# wg2fa
Wireguard 2fa solution using oauth2

## Flow Ideas (updated 1/14):
* user performs oauth with 2fa
* user provides a public key to newUser API
* wg2fa builds a *client* wireguard config
* wg2fa updates wireguard server config
* wg2fa adds client to a watch list
    * client is removed from the server config when:
        * they hit `n` minutes innactive
        * OR they hit `m` minutes regardless (optional)
* wg2fa returns a wireguard client config

# Credits
utilizes code from https://github.com/okta/samples-golang (Apache 2.0 licensed)


### TODOs
* finish initial smoke test of NewUser
    * need to change the client list from that json flat file to sqlite to keep my sanity
* write tests for wireguard conf functions
    * this is _started_ for `wg0.conf` but needs more testing
* create watchdog timer
* change users list fromo a json file to sql/sqlite
    * probably starting with sqlite
* Change to config file and make it easy
