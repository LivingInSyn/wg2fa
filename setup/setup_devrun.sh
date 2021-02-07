sudo apt -y update
sudo apt -y upgrade
sudo apt -y install build-essential
sudo apt -y install git
git clone https://github.com/LivingInSyn/wg2fa.git
cd wg2fa

# install go if it doesn't already exist:
if `go --version` ; then
	echo "go installed, continuing"
else
    # test if it's just not on the path
    if test -f "/usr/local/go/bin/go" ; then
        export PATH=$PATH:/usr/local/go/bin
    else
        wget https://golang.org/dl/go1.15.8.linux-amd64.tar.gz
        tar -C /usr/local -xzf go1.15.8.linux-amd64.tar.gz
        export PATH=$PATH:/usr/local/go/bin
    fi
fi

# clean old wireguard configs
rm -rf /etc/wireguard/privatekey
rm -rf /etc/wireguard/publickey
rm -rf /etc/wireguard/wg0.conf
# install wireguard if it doesn't exist
if `wg --version` ; then
    echo "wireguard already installed"
else
    sudo apt -y install wireguard
fi
# config wiregurad
sudo cp ./setup/wg0.conf /etc/wireguard/wg0.conf
sudo wg genkey | sudo tee /etc/wireguard/privatekey | wg pubkey | sudo tee /etc/wireguard/publickey
sudo sed -i "s/SERVER_PRIVATE_KEY/$(cat /etc/wireguard/privatekey)/g" /etc/wireguard/wg0.conf
sudo chmod 600 /etc/wireguard/privatekey
sudo chmod 600 /etc/wireguard/wg0.conf

#sudo make wireguard
sudo make wgup
sudo make dangerrun
