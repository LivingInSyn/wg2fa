sudo apt -y update
sudo apt -y upgrade
sudo apt -y install build-essential
sudo apt -y install git
git clone https://github.com/LivingInSyn/wg2fa.git
cd wg2fa
sudo make go
sudo make wireguard
sudo make wgup
sudo make dangerrun
