sudo apt install build-essential
sudo apt install git
git clone https://github.com/LivingInSyn/wg2fa.git
cd wg2fa
sudo make go
sudo make wireguard
sudo make wgup
sudo make dangerrun
