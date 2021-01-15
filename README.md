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


### TODOs
* Finish pulling in okta code for oauth flow
    * https://github.com/okta/samples-golang/blob/develop/okta-hosted-login/main.go
* add auth to newUser API
* create watchdog timer
* change users list fromo a json file to sql/sqlite
    * probably starting with sqlite
* Change to config file and make it easy
