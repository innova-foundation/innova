# Innova v5.0.0.3 release notes

v5.0.0.3 makes syncing faster, stops a node from freezing when a block pays a
collateral node it has not heard of, and fixes the macOS download. It changes no
consensus rule: every v5.0.0.x node accepts the same blocks.

## Who should upgrade

Everyone, especially nodes that sync or restart while behind the tip, and macOS
users.

## Faster sync

Two checks every block runs walked far back through the chain:

- The adaptive block size limit read 51,000 earlier blocks and sorted 50,000 sizes
  for a long-term cap. That cap is at least 300 KB x 50 = 15 MB, above the 8 MB
  ceiling, so it never changes the limit. The node now skips it.
- Epoch-state lookups walked back block by block to the finalized height, which is
  every block back to genesis while nothing is finalized. They now use the skip
  pointers each block index already keeps.

Both return exactly what they did before. On mainnet data a node synced 188 blocks
per second, against 75 on v5.0.0.2.

## No freeze on an unknown collateral node

When a block paid a collateral node the local list did not have yet, the node read
every block back to height 1 looking for its collateral, holding the main lock the
whole time (about 13 minutes on a fast machine). For any normal address that search
can never succeed: it tests each candidate by spending it with the payee's own
script and no signature. The node now skips it, asks its peers for the list at once,
and gives the same answer as before.

A node that is still catching up does not take collateral-node announcements yet, so
it retries each block paying a collateral node it has not heard of and moves through
those blocks more slowly. Nodes at the tip are not affected.

## macOS

The disk image now opens on a Mac without Homebrew, and macOS no longer reports it
as damaged. Qt and the libraries it needs are bundled into `Innova.app`, and the app
is signed after the last change to it. The daemon is at
`Innova.app/Contents/MacOS/innovad`.

The app is not notarized, so the first launch shows Apple's unidentified-developer
warning. Open it once with **System Settings > Privacy & Security > Open Anyway**,
or run:

```sh
xattr -dr com.apple.quarantine /Applications/Innova.app
```

## Verification

- Unit tests compare the new size limit and ancestor lookup against the previous
  code on random block chains, and check which payee scripts skip the search.
- A copy of the mainnet chain synced 12,572 blocks in 76 seconds, past the first
  collateral-node payment (8,161,864), with no chain search; v5.0.0.2 froze there
  for about 13 minutes.
