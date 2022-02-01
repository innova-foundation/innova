#!/bin/sh

sudo apt-get install unzip -y

wget https://github.com/innova-foundation/innova/releases/download/v4.3.9.1/innovabootstrap.zip
mv innovabootstrap.zip /root/.innova/innovabootstrap.zip
killall -9 innovad

sleep 10

cd /root/.innova
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

unzip innovabootstrap.zip
mv /root/.innova/innovabootstrap/* /root/.innova/
rm ./innovabootstrap.zip
rm -rf /root/.innova/innovabootstrap
sleep 5
echo Starting Innova daemon
innovad -daemon
echo Please wait....
sleep 60
innovad getinfo
echo Bootstrap completed
