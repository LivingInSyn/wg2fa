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

## build notes on windows
This requires gcc for sqlite. tdm-gcc is the only one that works for me: https://jmeubank.github.io/tdm-gcc/download/

```script
go get github.com/mattn/go-sqlite3
```


### TODOs
* finish initial smoke test of NewUser
    * identify missing testing
* refactor create user exec calls to be unit testable
* write watchdog unit tests
    * includes refactor to add channel to kill watchdog loop
* Change to config file and make it easy
