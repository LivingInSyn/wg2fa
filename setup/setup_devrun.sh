sudo apt install build-essential
sudo apt install git
git clone https://github.com/LivingInSyn/wg2fa.git
cd wg2fa
make go
make wireguard
make wgup
make dangerrun
