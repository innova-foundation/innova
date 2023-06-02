#!/bin/sh
GREEN='\033[0;32m'
RED='\033[0;31m'
COL_RESET='\033[0m'

echo
echo -e "$GREEN Innova Bootstrap Installer Script $COL_RESET"
echo
sudo apt-get install unrar -y
echo -e "$GREEN Downloading Bootstrap $COL_RESET"
wget https://github.com/innova-foundation/innova/releases/download/v4.3.9.5/innovabootstrap.rar
mv innovabootstrap.rar ~/.innova/innovabootstrap.rar
killall -9 innovad

sleep 10

echo
echo -e "$GREEN Cleaning Innova Core Folder $COL_RESET"
echo
mkdir ~/.innova
cd ~/.innova
rm -R ./database &>/dev/null &
rm -R ./smsgDB &>/dev/null &
rm -R ./txleveldb	&>/dev/null &
rm banlist.dat  &>/dev/null &
rm blk0001.dat  &>/dev/null &
rm innovanamesindex.dat  &>/dev/null &
rm peers.dat  &>/dev/null &
rm smsg.ini &>/dev/null &
rm debug.log &>/dev/null &

sleep 10

echo
echo -e "$GREEN Extracting Bootstrap $COL_RESET"
echo
unrar x -r innovabootstrap.rar
mv innovabootstrap/* ~/.innova/
rm innovabootstrap.rar
rm -rf ~/.innova/innovabootstrap
sleep 5
echo -e "$GREEN Starting Innova daemon $COL_RESET"
innovad
echo -e "$RED Please wait.... $COL_RESET"
sleep 75
innovad getinfo
echo -e "$GREEN Bootstrap completed $COL_RESET"