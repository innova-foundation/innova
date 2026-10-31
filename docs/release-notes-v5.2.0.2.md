Mandatory update. v5.2.0.2 is the network standard: it disconnects peers older than v5.2.0.2 (protocol 52002). Chain rules are unchanged and the hard fork stays at block 8,547,840.

- Version strings now show the real release (`v5.2.0.2-g<commit>`) instead of the nearest older tag.
- Bootstrap: downloads come as checked parts from the newest release that has them, and extraction works again (the bundled unzip code is now zlib 1.3.1's minizip, which handles multi-file and over-4 GB zips). A failed download leaves the data folder untouched and the wallet says so. Test networks never download the mainnet bootstrap.
- Qt: on first launch without chain data, choose between downloading the bootstrap and syncing from the network; the splash screen shows download progress.
- Qt: the debug window's Information tab shows the mergeset fork and the free-migration window.
- `innova-cli help` lists commands by group (wallet, privacy, blockchain, network, mining, staking, messaging, control).
- The terminal banner shows the right P2P port on testnet and regtest.
- `contrib/make_bootstrap.sh` builds the bootstrap parts and checksum file from a stopped node.
