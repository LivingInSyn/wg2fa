# wg2fa
Wireguard 2fa solution utilizing routing as access control


## Flow Ideas:
* wg2fa controls creating a user, either accepting a private key or generating one
* when users are created they can only talk to wg2fa controlled by routing in the wireguard config
* after connecting to wireguard, users must 2fa authenticate to wg2fa
* wg2fa will then update the routing config from "only wg2fa" to the users configured routing
    * step 1 will be "can go anywhere once authed" probably
* wg2fa has a thread which monitors user innactivity. On innactivity for some (to be configurable) `n` minutes it will:
    * change the routing back to "only talk to wg2fa"