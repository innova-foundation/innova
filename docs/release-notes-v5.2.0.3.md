Recommended update before the hard fork at block 8,547,840. Chain rules are unchanged; peers older than v5.2.0.2 (protocol 52002) are still refused.

- Bootstrap: downloads work on Windows and macOS again (system certificate store), fall back to older releases, resume dropped parts and check disk space first.
- Bootstrap: a node that is far behind can replace its partial chain from the bootstrap (Qt Settings > Replace Chain with Bootstrap, or `downloadbootstrap` then restart). The wallet is never touched, and a crash mid-apply rolls back or finishes on the next start.
- macOS: the app bundle carries all its libraries.
- Sync: about twice as fast on a hard disk (one disk flush per batch instead of per block), side-branch headers served on request, orphan and stall fixes, less memory once synced.
- Startup checks the last 288 blocks; a bad block at startup stops with instructions instead of silently rewinding.
- Secure messaging is on by default (`smsg=0` turns it off).
- Removed: the signed sync-checkpoint system (`getcheckpoint`, `-checkpointkey`, `-cppolicy`), NullSend v1 (`z_nullsend`), the Darksend mixing RPCs (`startmixing`, `stopmixing`, `getmixingstatus`, `getpoolinfo`), sporks, the ANON wallet RPCs, `getblock_old` and the `masternode` alias.
- A data folder created by v5.2.0.3 cannot be opened by v5.2.0.2.
- `contrib/make_bootstrap.sh` now takes the chain height as its third argument and writes it into the checksum file.
