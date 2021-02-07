# wireguard:
# 	# install wireguard
# 	apt -y install wireguard
# 	# setup keys and conf files
# 	cp ./setup/wg0.conf /etc/wireguard/wg0.conf
# 	wg genkey | sudo tee /etc/wireguard/privatekey | wg pubkey | sudo tee /etc/wireguard/publickey
# 	sed -i "s/SERVER_PRIVATE_KEY/$(cat /etc/wireguard/privatekey)/g" /etc/wireguard/wg0.conf
# 	chmod 600 /etc/wireguard/privatekey
# 	chmod 600 /etc/wireguard/wg0.conf

wgup:
	# start wireguard
	wg-quick up wg0

build:
	go build -o wg2fa

run:
	go run main.go

dangerrun:
	./wg2fa --wgc /etc/wireguard/wg0.conf --cl /etc/wireguard/clientDB --dangerauth --debug --cid a --iss b