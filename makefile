wireguard:
	# install wireguard
	apt -y install wireguard
	# setup keys and conf files
	cp ./setup/wg0.conf /etc/wireguard/wg0.conf
	wg genkey | sudo tee /etc/wireguard/privatekey | wg pubkey | sudo tee /etc/wireguard/publickey
	cp ./wg0.conf /etc/wireguard/
	sed -i "s/SERVER_PRIVATE_KEY/$(cat /etc/wireguard/privatekey)/g" /etc/wireguard/wg0.conf
	chmod 600 /etc/wireguard/privatekey
	chmod 600 /etc/wireguard/wg0.config

wgup:
	# start wireguard
	wg-quick up wg0

go:
	wget https://golang.org/dl/go1.15.8.linux-amd64.tar.gz
	tar -C /usr/local -xzf go1.15.8.linux-amd64.tar.gz
	export PATH=$PATH:/usr/local/go/bin

build:
	go build -o wg2fa

run:
	go run main.go

dangerrun: build
	./wg2fa --wgc /etc/wireguard/wg0.conf --cl /etc/wireguard/clientDB --dangerauth --debug --cid a --iss b