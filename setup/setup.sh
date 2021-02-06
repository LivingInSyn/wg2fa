# download go and put it on the path
wget https://golang.org/dl/go1.15.8.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.15.8.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
# install wireguard
sudo apt install wireguard
# build the server public and private keys
wg genkey | sudo tee /etc/wireguard/privatekey | wg pubkey | sudo tee /etc/wireguard/publickey
# move the sample wireguard config over
cp ./wg0.conf /etc/wireguard/
sudo sed -i "s/SERVER_PRIVATE_KEY/$(cat /etc/wireguard/privatekey)/g" /etc/wireguard/wg0.conf
# update permissions
sudo chmod 600 /etc/wireguard/privatekey
sudo chmod 600 /etc/wireguard/wg0.config

#startup with systemd (un comment)
sudo wg-quick up wg0
#sudo systemctl enable wg-quick@wg0
#sudo systemctl start wg-quick@wg0

# download and build wg2fa
wget https://github.com/LivingInSyn/wg2fa/archive/main.zip
unzip main.zip
cd wg2fa-main
go build -o wg2fa
# start wg2fa
sudo ./wg2fa --wgc /etc/wireguard/wg0.conf --cl /etc/wireguard/clientDB \
--dangerauth \
--debug \
--cid a \
--iss b
