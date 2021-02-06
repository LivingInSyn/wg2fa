# Install Instructions

## Automatic install
### normal install
This script does not auto start wg2fa or wireguard
```
wget https://raw.githubusercontent.com/LivingInSyn/wg2fa/main/setup/setup.sh | sh
```
### dev autorun
```
wget https://raw.githubusercontent.com/LivingInSyn/wg2fa/main/setup/setup_devrun.sh | sh
```

## manual server setup instructions

### Install Wireguard
First install wireguard and setup the server keys
```shell
# install wireguard
sudo apt install wireguard
# build the server public and private keys
wg genkey | sudo tee /etc/wireguard/privatekey | wg pubkey | sudo tee /etc/wireguard/publickey
```

### Create wireguard conf
Next Create the config file `/etc/wireguard/wg0.conf` replacing SERVER_PRIVATE_KEY with the contents of `/etc/wireguard/privatekey`
```
[Interface]
Address = 10.0.0.1/24
SaveConfig = true
ListenPort = 51820
PrivateKey = SERVER_PRIVATE_KEY
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ens3 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ens3 -j MASQUERADE
```
*note*: you can write this file as (sample wg0.conf in this directory) is and then run: 
```shell
sudo sed -i "s/SERVER_PRIVATE_KEY/$(cat /etc/wireguard/privatekey)/g" test.conf
```

*note 2*: You MAY have to update the pre and post routing IPTables config.  Replace eth0 with the interface you want wireguard to egress from

### Check your permissions
Next check your permissions on the files we created.

```shell
sudo chmod 600 /etc/wireguard/{privatekey,wg0.conf}
```

# Create directories used by wg2fa 
Some of these are optional and/or configurable. This documentation is to be updated
```shell
sudo mkdir /etc/wireguard/clientKey
sudo mkdir /etc/wireguard/clientConfigs
sudo mkdir /etc/wireguard/clientList
```

# Start up wireguard with systemd
```shell
sudo systemctl enable wg-quick@wg0
```