#!/bin/bash
TEMP=/tmp/answer$$
whiptail --title "Innova [INN]"  --menu  "Ubuntu 16.04/18.04/20.04 PreBuilt Daemon Node :" 20 0 0 1 "Grab innovad Ubuntu 16.04" 2 "Update innovad 16.04" 3 "Grab innovad Ubuntu 18.04" 4 "Update innovad 18.04" 5 "Grab innovad Ubuntu 20.04" 6 "Update innovad 20.04" 2>$TEMP
choice=`cat $TEMP`
case $choice in
1) echo 1 "Grabbing innovad Ubuntu 16.04 from Github"

echo "Updating linux packages"
sudo apt-get update -y && sudo apt-get upgrade -y

sudo apt-get --assume-yes install git unzip build-essential libssl-dev libdb++-dev libboost-all-dev libqrencode-dev libminiupnpc-dev libevent-dev obfs4proxy libcurl4-openssl-dev

echo "Add Firewall Rules"
sudo apt-get install ufw
sudo ufw allow ssh
sudo ufw limit ssh/tcp
sudo ufw allow 14530/tcp
sudo ufw allow 14531/tcp
sudo ufw allow 14539/tcp
sudo ufw default allow outgoing
sudo ufw enable

echo "Setting Swap File"
sudo swapoff -a
sudo fallocate -l 8G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' >> sudo /etc/fstab

echo "Installing Innova Wallet"
wget https://github.com/innova-foundation/innova/releases/download/v4.3.9.3/innovad-16.zip
unzip innovad-16.zip
mv innovad-16/innovad innovad
rm -r innovad-16
rm -r innovad-16.zip
chmod ugo+x innovad
sudo cp -rf innovad /usr/bin/
echo "Copied to /usr/bin for ease of use"

echo "Get Chaindata"
bash -c "$(wget -O - https://raw.githubusercontent.com/innova-foundation/innova/master/bootstrap.sh)"

echo "Back to Compiled innovad Binary Folder"
cd ~/innova/src
                ;;
2) echo 2 "Update innovad 16.04 from Github"
echo "Updating Innova Wallet"
wget https://github.com/innova-foundation/innova/releases/download/v4.3.9.3/innovad-16.zip
unzip innovad-16.zip
mv innovad-16/innovad innovad
rm -r innovad-16
rm -r innovad-16.zip
chmod ugo+x innovad
sudo cp -rf innovad /usr/bin/
echo "Copied to /usr/bin for ease of use"

echo "Back to Compiled innovad Binary Folder"
cd ~/innova/src
                ;;
3) echo 3 "Grabbing innovad Ubuntu 18.04 from Github"
echo "Updating linux packages"
sudo apt-get update -y && sudo apt-get upgrade -y

sudo apt-get --assume-yes install git unzip build-essential libdb++-dev libboost-all-dev libqrencode-dev libminiupnpc-dev libevent-dev obfs4proxy libssl-dev libcurl4-openssl-dev

echo "Add Firewall Rules"
sudo apt-get install ufw
sudo ufw allow ssh
sudo ufw limit ssh/tcp
sudo ufw allow 14530/tcp
sudo ufw allow 14531/tcp
sudo ufw allow 14539/tcp
sudo ufw default allow outgoing
sudo ufw enable

echo "Setting Swap File"
sudo swapoff -a
sudo fallocate -l 8G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' >> sudo /etc/fstab

echo "Installing Innova Wallet"
wget https://github.com/innova-foundation/innova/releases/download/v4.3.9.3/innovad-18.zip
unzip innovad-18.zip
mv innovad-18/innovad innovad
rm -r innovad-18
rm -r innovad-18.zip
chmod ugo+x innovad
sudo cp -rf innovad /usr/bin/
echo "Copied to /usr/bin for ease of use"

echo "Get Chaindata"
bash -c "$(wget -O - https://raw.githubusercontent.com/innova-foundation/innova/master/bootstrap.sh)"

echo "Back to Compiled innovad Binary Folder"
cd ~/innova/src
                ;;
4) echo 4 "Update innovad 18.04 from Github"
echo "Updating Innova Wallet"
wget https://github.com/innova-foundation/innova/releases/download/v4.3.9.3/innovad-18.zip
unzip innovad-18.zip
mv innovad-18/innovad innovad
rm -r innovad-18
rm -r innovad-18.zip
chmod ugo+x innovad
sudo cp -f innovad /usr/bin/
echo "Copied to /usr/bin for ease of use"

echo "Back to Compiled innovad Binary Folder"
cd ~/innova/src
                ;;
5) echo 5 "Grabbing innovad Ubuntu 20.04 from Github"
echo "Updating linux packages"
sudo apt-get update -y && sudo apt-get upgrade -y

sudo apt-get --assume-yes install git unzip build-essential libdb++-dev libboost-all-dev libqrencode-dev libminiupnpc-dev libevent-dev obfs4proxy libssl-dev libcurl4-openssl-dev

echo "Add Firewall Rules"
sudo apt-get install ufw
sudo ufw allow ssh
sudo ufw limit ssh/tcp
sudo ufw allow 14530/tcp
sudo ufw allow 14531/tcp
sudo ufw allow 14539/tcp
sudo ufw default allow outgoing
sudo ufw enable

echo "Setting Swap File"
sudo swapoff -a
sudo fallocate -l 8G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' >> sudo /etc/fstab

echo "Installing Innova Wallet"
wget https://github.com/innova-foundation/innova/releases/download/v4.3.9.3/innovad-20.zip
unzip innovad-20.zip
mv innovad-20/innovad innovad
rm -r innovad-20
rm -r innovad-20.zip
chmod ugo+x innovad
sudo cp -f innovad /usr/bin/
echo "Copied to /usr/bin for ease of use"

echo "Get Chaindata"
bash -c "$(wget -O - https://raw.githubusercontent.com/innova-foundation/innova/master/bootstrap.sh)"

echo "Back to Compiled innovad Binary Folder"
cd ~/innova/src
                ;;
6) echo 6 "Update innovad 20.04 from Github"
echo "Updating Innova Wallet"
wget https://github.com/innova-foundation/innova/releases/download/v4.3.9.3/innovad-20.zip
unzip innovad-20.zip
mv innovad-20/innovad innovad
rm -r innovad-20
rm -r innovad-20.zip
chmod ugo+x innovad
sudo cp -f innovad /usr/bin/
echo "Copied to /usr/bin for ease of use"

echo "Back to Compiled innovad Binary Folder"
cd ~/innova/src
              ;;
esac
echo Selected $choice
