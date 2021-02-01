# install wireguard
sudo apt install wireguard
# build the server public and private keys
wg genkey | sudo tee /etc/wireguard/privatekey | wg pubkey | sudo tee /etc/wireguard/publickey
# move the sample wireguard config over
cp ./wg0.conf /etc/wireguard/
sudo sed -i "s/SERVER_PRIVATE_KEY/$(cat /etc/wireguard/privatekey)/g" /etc/wireguard/wg0.conf
# update permissions
sudo chmod 600 /etc/wireguard/{privatekey,wg0.conf}
# create wg2fa dirs
#sudo mkdir /etc/wireguard/clientConfigs
#sudo mkdir /etc/wireguard/clientList
#startup with systemd (un comment)
#sudo systemctl enable wg-quick@wg0
#sudo systemctl start wg-quick@wg0
