#!/bin/bash
TEMP=/tmp/answer$$
whiptail --title "Innova [INN]"  --menu  "Ubuntu 16.04/18.04/20.04 QT Wallet :" 20 0 0 1 "Compile Innova QT Ubuntu 16.04" 2 "Update Innova QT 16.04 to latest" 3 "Compile Innova QT Ubuntu 18.04" 4 "Update Innova QT 18.04 to latest" 5 "Compile Innova QT Ubuntu 20.04" 6 "Update Innova QT 20.04 to latest" 2>$TEMP
choice=`cat $TEMP`
case $choice in
1) echo 1 "Compiling Innova QT Ubuntu 16.04"

echo "Updating linux packages"
sudo apt-get update -y && sudo apt-get upgrade -y

sudo apt-get install -y git unzip build-essential libssl-dev libdb++-dev libboost-all-dev libqrencode-dev libminiupnpc-dev libevent-dev autogen automake  libtool libqt5gui5 libqt5core5a libqt5dbus5 qttools5-dev qttools5-dev-tools qt5-default libcurl4-openssl-dev

echo "Installing Innova Wallet"
git clone https://github.com/innova-foundation/innova
cd innova || exit
git checkout master
git pull

#echo "Change line in innova-qt.pro from stdlib=c99 to stdlib=gnu99"
#sed -i 's/c99/gnu99/' ~/innova/innova-qt.pro

echo "Change line in innova-qt.pro"
sed -i 's/LIBS += -lcurl -lssl -lcrypto -lcrypt32 -lssh2 -lgcrypt -lidn2 -lgpg-error -lunistring -lwldap32 -ldb_cxx$$BDB_LIB_SUFFIX/LIBS += -lcurl -lssl -lcrypto -ldb_cxx$$BDB_LIB_SUFFIX/' ~/innova/innova-qt.pro

echo "Building Qt Wallet"
qmake "USE_UPNP=1" "USE_QRCODE=1" OPENSSL_INCLUDE_PATH=/usr/local/ssl/include OPENSSL_LIB_PATH=/usr/local/ssl/lib innova-qt.pro
make

echo "Get Chaindata"
mkdir ~/.innova
cd ~/.innova || exit
rm -rf database txleveldb smsgDB
wget https://github.com/innova-foundation/innova/releases/download/v4.3.9.1/innovabootstrap.zip
unzip innovabootstrap.zip
rm innovabootstrap.zip
Echo "Back to Compiled QT Binary Folder"
cd ~/innova/src
                ;;
2) echo 2 "Update Innova QT"
echo "Updating Innova Wallet"
cd ~/innova || exit
git checkout master
git pull

#echo "Change line in innova-qt.pro from stdlib=c99 to stdlib=gnu99"
#sed -i 's/c99/gnu99/' ~/innova/innova-qt.pro

echo "Change line in innova-qt.pro"
sed -i 's/LIBS += -lcurl -lssl -lcrypto -lcrypt32 -lssh2 -lgcrypt -lidn2 -lgpg-error -lunistring -lwldap32 -ldb_cxx$$BDB_LIB_SUFFIX/LIBS += -lcurl -lssl -lcrypto -ldb_cxx$$BDB_LIB_SUFFIX/' ~/innova/innova-qt.pro

echo "Building Qt Wallet"
qmake "USE_UPNP=1" "USE_QRCODE=1" OPENSSL_INCLUDE_PATH=/usr/local/ssl/include OPENSSL_LIB_PATH=/usr/local/ssl/lib innova-qt.pro
make

echo "Back to Compiled QT Binary Folder"
cd ~/innova
                ;;
3) echo 3 "Compile Innova QT Ubuntu 18.04"
echo "Updating linux packages"
sudo apt-get update -y && sudo apt-get upgrade -y

sudo apt-get install -y git unzip build-essential libdb++-dev libboost-all-dev libqrencode-dev libminiupnpc-dev libevent-dev autogen automake libtool libqt5gui5 libqt5core5a libqt5dbus5 qttools5-dev qttools5-dev-tools qt5-default libcurl4-openssl-dev

echo "Downgrade libssl-dev"
sudo apt-get install make
wget https://ftp.openssl.org/source/old/1.0.1/openssl-1.0.1j.tar.gz
tar -xzvf openssl-1.0.1j.tar.gz
cd openssl-1.0.1j
./config
make depend
sudo make install
sudo ln -sf /usr/local/ssl/bin/openssl `which openssl`
cd ~
openssl version -v

echo "Installing Innova Wallet"
git clone https://github.com/innova-foundation/innova
cd innova
git checkout master
git pull

#echo "Change line in innova-qt.pro from stdlib=c99 to stdlib=gnu99"
#sed -i 's/c99/gnu99/' ~/innova/innova-qt.pro

echo "Change line in innova-qt.pro"
sed -i 's/LIBS += -lcurl -lssl -lcrypto -lcrypt32 -lssh2 -lgcrypt -lidn2 -lgpg-error -lunistring -lwldap32 -ldb_cxx$$BDB_LIB_SUFFIX/LIBS += -lcurl -lssl -lcrypto -ldb_cxx$$BDB_LIB_SUFFIX/' ~/innova/innova-qt.pro

echo "Building Qt Wallet"
qmake "USE_UPNP=1" "USE_QRCODE=1" OPENSSL_INCLUDE_PATH=/usr/local/ssl/include OPENSSL_LIB_PATH=/usr/local/ssl/lib innova-qt.pro
make

echo "Get Chaindata"
mkdir ~/.innova
cd ~/.innova
rm -rf database txleveldb smsgDB
wget https://github.com/innova-foundation/innova/releases/download/v4.3.9.1/innovabootstrap.zip
unzip innovabootstrap.zip
rm innovabootstrap.zip
Echo "Back to Compiled QT Binary Folder"
cd ~/innova/src
                ;;
4) echo 4 "Update Innova QT 18.04"
echo "Updating Innova Wallet"
cd ~/innova || exit
git checkout master
git pull

#echo "Change line in innova-qt.pro from stdlib=c99 to stdlib=gnu99"
#sed -i 's/c99/gnu99/' ~/innova/innova-qt.pro

echo "Change line in innova-qt.pro"
sed -i 's/LIBS += -lcurl -lssl -lcrypto -lcrypt32 -lssh2 -lgcrypt -lidn2 -lgpg-error -lunistring -lwldap32 -ldb_cxx$$BDB_LIB_SUFFIX/LIBS += -lcurl -lssl -lcrypto -ldb_cxx$$BDB_LIB_SUFFIX/' ~/innova/innova-qt.pro

echo "Building Qt Wallet"
qmake "USE_UPNP=1" "USE_QRCODE=1" OPENSSL_INCLUDE_PATH=/usr/local/ssl/include OPENSSL_LIB_PATH=/usr/local/ssl/lib innova-qt.pro
make

echo "Back to Compiled QT Binary Folder"
cd ~/innova
                ;;
5) echo 5 "Compile Innova QT Ubuntu 20.04"
echo "Updating linux packages"
sudo apt-get update -y && sudo apt-get upgrade -y

sudo apt-get install -y git unzip build-essential libdb++-dev libboost-all-dev libqrencode-dev libminiupnpc-dev libevent-dev autogen automake libtool libqt5gui5 libqt5core5a libqt5dbus5 qttools5-dev qttools5-dev-tools qt5-default libcurl4-openssl-dev

echo "Downgrade libssl-dev"
sudo apt-get install make
wget https://ftp.openssl.org/source/old/1.0.1/openssl-1.0.1j.tar.gz
tar -xzvf openssl-1.0.1j.tar.gz
cd openssl-1.0.1j
./config
make depend
sudo make install
sudo ln -sf /usr/local/ssl/bin/openssl `which openssl`
cd ~
openssl version -v

echo "Installing Innova Wallet"
git clone https://github.com/innova-foundation/innova
cd innova
git checkout master
git pull

#echo "Change line in innova-qt.pro from stdlib=c99 to stdlib=gnu99"
#sed -i 's/c99/gnu99/' ~/innova/innova-qt.pro

echo "Change line in innova-qt.pro"
sed -i 's/LIBS += -lcurl -lssl -lcrypto -lcrypt32 -lssh2 -lgcrypt -lidn2 -lgpg-error -lunistring -lwldap32 -ldb_cxx$$BDB_LIB_SUFFIX/LIBS += -lcurl -lssl -lcrypto -ldb_cxx$$BDB_LIB_SUFFIX/' ~/innova/innova-qt.pro

echo "Fix Qt in Ubuntu 20.04 WSLv1"
sudo strip --remove-section=.note.ABI-tag /usr/lib/x86_64-linux-gnu/libQt5Core.so.5

echo "Building Qt Wallet"
qmake "USE_UPNP=1" "USE_QRCODE=1" OPENSSL_INCLUDE_PATH=/usr/local/ssl/include OPENSSL_LIB_PATH=/usr/local/ssl/lib innova-qt.pro
make


echo "Get Chaindata"
mkdir ~/.innova
cd ~/.innova
rm -rf database txleveldb smsgDB
wget https://github.com/innova-foundation/innova/releases/download/v4.3.9.1/innovabootstrap.zip
unzip innovabootstrap.zip
rm innovabootstrap.zip
Echo "Back to Compiled QT Binary Folder"
cd ~/innova/src
                ;;
6) echo 6 "Update Innova QT 20.04"
echo "Updating Innova Wallet"
cd ~/innova || exit
git checkout master
git pull

#echo "Change line in innova-qt.pro from stdlib=c99 to stdlib=gnu99"
#sed -i 's/c99/gnu99/' ~/innova/innova-qt.pro

echo "Change line in innova-qt.pro"
sed -i 's/LIBS += -lcurl -lssl -lcrypto -lcrypt32 -lssh2 -lgcrypt -lidn2 -lgpg-error -lunistring -lwldap32 -ldb_cxx$$BDB_LIB_SUFFIX/LIBS += -lcurl -lssl -lcrypto -ldb_cxx$$BDB_LIB_SUFFIX/' ~/innova/innova-qt.pro

echo "Fix Qt in Ubuntu 20.04 WSLv1"
sudo strip --remove-section=.note.ABI-tag /usr/lib/x86_64-linux-gnu/libQt5Core.so.5

echo "Building Qt Wallet"
qmake "USE_UPNP=1" "USE_QRCODE=1" OPENSSL_INCLUDE_PATH=/usr/local/ssl/include OPENSSL_LIB_PATH=/usr/local/ssl/lib innova-qt.pro
make

echo "Back to Compiled QT Binary Folder"
cd ~/innova
                ;;
5) echo 5 "Compile Innova QT Ubuntu 20.04"
echo "Updating linux packages"
sudo apt-get update -y && sudo apt-get upgrade -y

sudo apt-get install -y git unzip build-essential libdb++-dev libboost-all-dev libqrencode-dev libminiupnpc-dev libevent-dev autogen automake libtool libqt5gui5 libqt5core5a libqt5dbus5 qttools5-dev qttools5-dev-tools qt5-default libcurl4-openssl-dev

echo "Downgrade libssl-dev"
sudo apt-get install make
wget https://ftp.openssl.org/source/old/1.0.1/openssl-1.0.1j.tar.gz
tar -xzvf openssl-1.0.1j.tar.gz
cd openssl-1.0.1j
./config
make depend
sudo make install
sudo ln -sf /usr/local/ssl/bin/openssl `which openssl`
cd ~
openssl version -v

echo "Installing Innova Wallet"
git clone https://github.com/innova-foundation/innova
cd innova
git checkout master
git pull

#echo "Change line in innova-qt.pro from stdlib=c99 to stdlib=gnu99"
#sed -i 's/c99/gnu99/' ~/innova/innova-qt.pro

qmake "USE_UPNP=1" "USE_QRCODE=1" OPENSSL_INCLUDE_PATH=/usr/local/ssl/include OPENSSL_LIB_PATH=/usr/local/ssl/lib innova-qt.pro
make


echo "Get Chaindata"
cd ~/.innova
rm -rf database txleveldb smsgDB
wget https://github.com/innova-foundation/innova/releases/download/v4.3.9.1/innovabootstrap.zip
unzip innovabootstrap.zip
rm innovabootstrap.zip
Echo "Back to Compiled QT Binary Folder"
cd ~/innova/src
              ;;
6) echo 6 "Update Innova QT 20.04"
echo "Updating Innova Wallet"
cd ~/innova || exit
git checkout master
git pull

#echo "Change line in innova-qt.pro from stdlib=c99 to stdlib=gnu99"
#sed -i 's/c99/gnu99/' ~/innova/innova-qt.pro

qmake "USE_UPNP=1" "USE_QRCODE=1" OPENSSL_INCLUDE_PATH=/usr/local/ssl/include OPENSSL_LIB_PATH=/usr/local/ssl/lib innova-qt.pro
make
echo "Back to Compiled QT Binary Folder"
cd ~/innova
              ;;
esac
echo Selected $choice
