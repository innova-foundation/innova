# Innova [INN]
Tribus Algo PoW/PoS Hybrid Cryptocurrency

![logo](http://i.imgur.com/gIe5vnw.png)

[![GitHub version](https://img.shields.io/github/release/carsenk/innova.svg)](https://badge.fury.io/gh/carsenk%2Finnova)
[![License: GPL v3](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/carsenk/innova/blob/master/COPYING)
[![Innova downloads](https://img.shields.io/github/downloads/carsenk/innova/total.svg)](https://github.com/carsenk/innova/releases)
[![Innova lateat release downloads](https://img.shields.io/github/downloads/carsenk/innova/latest/total)](https://github.com/carsenk/innova/releases)
[![Join the chat at https://discord.gg/AcThv2y](https://img.shields.io/badge/Discord-Chat-blue.svg?logo=discord)](https://discord.gg/AcThv2y)

[![HitCount](http://hits.dwyl.io/carsenk/innova.svg)](http://hits.dwyl.io/carsenk/innova)
<a href="https://discord.gg/UPpQy3n"><img src="https://discordapp.com/api/guilds/334361453320732673/embed.png" alt="Discord server" /></a>

![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/carsenk/innova.svg) ![GitHub repo size in bytes](https://img.shields.io/github/repo-size/carsenk/innova.svg)

[![Snap Status](https://build.snapcraft.io/badge/carsenk/innova.svg)](https://build.snapcraft.io/user/carsenk/innova)

![Code Climate](https://codeclimate.com/github/carsenk/innova/badges/gpa.svg)

[![Build Status](https://travis-ci.org/carsenk/innova.svg?branch=master)](https://travis-ci.org/carsenk/innova)

[![Build history](https://buildstats.info/travisci/chart/carsenk/innova?branch=master)](https://travis-ci.org/carsenk/innova?branch=master)

Intro
==========================
Innova is a true optionally anonymous, untraceable, and secure hybrid cryptocurrency.

Ticker: D

Innova [INN] is an anonymous, untraceable, energy efficient, Proof-of-Work (New Tribus Algorithm) and Proof-of-Stake cryptocurrency.
10,000,000 INN will be created in approx. about 3 years during the PoW phase.

Supported Operating Systems
==========================
* Linux 64-bit
* Windows 64-bit
* macOS 10.11+

Install Innova with Snap on any Linux Distro
==========================
* `sudo apt install snapd`
* `sudo snap install innova`

* `innova` for running the QT
* `innova.daemon` for running innovad

Specifications
==========================
* Total number of coins: 10,000,000 D
* Ideal block time: 30 seconds
* Stake interest: 6% annual static inflation
* Confirmations: 10 blocks
* Maturity: 30 blocks (15 minutes)
* Min stake age: 8 hours

* Cost of Hybrid Fortuna Stakes: 5,000 D
* Hybrid Fortuna Stake Reward: 33% of the current block reward
* P2P Port: 14530, Testnet Port: 15530
* RPC Port: 14531, Testnet RPC Port: 15531
* Fortuna Stake Port: 14539, Testnet Port: 15539

* INN Magic Number: 0xa23d7e5c
* BIP44 CoinType: 116
* Base58 Pubkey Decimal: 30
* Base58 Scriptkey Decimal: 90
* Base58 Privkey Decimal: 158

Technology
==========================
* Hybrid PoW/PoS Fortuna Stakes
* Stealth addresses
* Ring Signatures (16 Recommended)
* Native Optional Tor Onion Node (-nativetor=1)
* Encrypted Messaging
* Multi-Signature Addresses & TXs
* Atomic Swaps using UTXOs (BIP65 CLTV)
* BIP39 Support (Coin Type 116)
* Proof of Data (Image/Data Timestamping)
* Fast 30 Second Block Times
* New/First Tribus PoW Algorithm comprising of 3 NIST5 algorithms
* Tribus PoW/PoS Hybrid
* Full decentralization

LINKS
==========================
* Official Website(https://innova.io/)
* Official Forums(https://innovatalk.org/)
* Innova Twitter(https://twitter.com/innovacoin)
* Innova Discord Chat(https://discord.gg/C64HXbc)

ASCII CAST TUTORIALS
==========================
[![asciicast](https://asciinema.org/a/179356.png)](https://asciinema.org/a/179356)
[![asciicast](https://asciinema.org/a/179362.png)](https://asciinema.org/a/179362)
[![asciicast](https://asciinema.org/a/179355.png)](https://asciinema.org/a/179355)

innovaqtubuntu.sh by Buzzkillb
===========================
Compile the latest Innova QT (Graphical Wallet) Ubuntu 16.04 or Ubuntu 18.04+

Credits to Buzzkillb for the creation of this bash script, original repository: https://github.com/buzzkillb/innova-qt/

Compiles Innova QT Ubuntu 16.04 or 18.04, Grabs latest chaindata, and populates innova.conf with addnodes or can update a previous compile to the latest master branch.  
```bash -c "$(wget -O - https://raw.githubusercontent.com/carsenk/innova/master/innovaqtubuntu.sh)"```  

To turn on nativetor in innova.conf  
```nativetor=1```  

![Innova Installer Menu](https://raw.githubusercontent.com/buzzkillb/innova-qt/master/compile-menu.PNG)  

Development process
===========================

Developers work in their own trees, then submit pull requests when
they think their feature or bug fix is ready.

The patch will be accepted if there is broad consensus that it is a
good thing.  Developers should expect to rework and resubmit patches
if they don't match the project's coding conventions (see coding.txt)
or are controversial.

The master branch is regularly built and tested, but is not guaranteed
to be completely stable. Tags are regularly created to indicate new
stable release versions of Innova.

Feature branches are created when there are major new features being
worked on by several people.

From time to time a pull request will become outdated. If this occurs, and
the pull is no longer automatically mergeable; a comment on the pull will
be used to issue a warning of closure. The pull will be closed 15 days
after the warning if action is not taken by the author. Pull requests closed
in this manner will have their corresponding issue labeled 'stagnant'.

Issues with no commits will be given a similar warning, and closed after
15 days from their last activity. Issues closed in this manner will be
labeled 'stale'.
