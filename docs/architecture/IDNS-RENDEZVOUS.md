# IDNS rendezvous descriptors

A rendezvous descriptor is an IDNS name value that points at a Tor onion service
instead of an IP address. It lets a name be registered, renewed and resolved
without the operator ever publishing where the service runs.

This is an application-layer convention. It changes no consensus rule, needs no
fork height, and does not touch the v5 activation ladder.

---

## 1. Why no consensus change is needed

Consensus never parses a name value. `checkNameValues` (`src/namecoin.cpp`)
applies one rule to `vchValue`:

```cpp
if (ret.vchValue.size() > MAX_VALUE_LENGTH)
    ret.err_msg.append("value is too long.\n");
```

`MAX_VALUE_LENGTH` is 20 KB (`src/namecoin.h`). The index guard
`ValidNameEffectRecord` checks the operation code and the same size bound and
nothing else. `getNameValue` returns the stored bytes verbatim and the name RPCs
echo them.

So a descriptor is not a new field. It is different bytes in a field the chain
already stores, and every rule that touches that field is indifferent to them.

A v1 descriptor is 72-76 bytes (75 with a four-digit port). Name fees scale at
one cent per 128 bytes, so a rendezvous registration costs exactly what a short A
record costs.

---

## 2. The v1 grammar

```
value    = "idnsrv" version ":" host ":" port
version  = 1*3DIGIT              ; no leading zero
host     = 56(LOWERBASE32) ".onion"
port     = 1*5DIGIT              ; 1..65535, no leading zero
```

`name_rendezvous_encode <onionhost> <port>` produces the canonical value; pass
its `value` field to `name_new` or `name_update`.

Example (a synthetic address; no service answers on it):

```
idnsrv1:ibaueq2eivdeoscjjjfuytkoj5ifcustkrkvmv2ylfnfwxc5lzprciqd.onion:8443
```

Rules the codec (`src/idnsdescriptor.cpp`) enforces:

- **Whole-value.** A value either *is* a descriptor or is a conventional record.
  There is no mixed form, so classification is a prefix test.
- **Printable ASCII only** (0x21–0x7E). The value transits `std::string`,
  `c_str()` and `snprintf` on the resolver path, so an embedded NUL would
  truncate it and a space would reshape it.
- **One canonical encoding per service.** Parsing refuses uppercase hostnames and
  refuses leading zeros in the version and the port. Construction
  (`BuildIDnsRendezvous`) lowercases the hostname, so an operator who pastes an
  uppercase address still writes the canonical bytes to the chain.
- **v3 addresses only.** The hostname must be 56 lowercase base32 characters
  whose decoded 35 bytes end in the address version byte `0x03`. v2 onion
  services were removed from the Tor network in 2021, so a v2-length address is
  refused rather than stored and never resolved.
- **The v3 checksum is not verified.** It is SHA3-256 based and this tree has no
  SHA3-256. A hostname that passes the shape check can still be one no service
  answers on; that failure surfaces as a failed dial, not as a bad registration.

The descriptor contains no `=`, `|`, `,` or `~`, which are the separators the
legacy value tokenizer uses. A legacy resolver reading a descriptor therefore
finds zero tokens for every query type and answers nothing — the fail-closed
behaviour below is what a build that predates this document already does by
accident, and what this build does deliberately.

---

## 3. Unknown tags fail closed

`ClassifyIDnsValue` returns one of three kinds:

| Kind | When | Effect |
| --- | --- | --- |
| `IDNS_VALUE_RECORD` | The value does not begin with `idnsrv` | Legacy resolver path, unchanged |
| `IDNS_VALUE_RENDEZVOUS` | Family, version 1, valid body | Dialable through the SOCKS5 endpoint |
| `IDNS_VALUE_UNSUPPORTED` | Family, but an unknown version or an invalid body | **Refused.** Not retried as a plain record |

**The decision: an unknown tag is refused, not resolved as a plain record.**

The reasoning is that a descriptor states an intent — "reach this name through a
rendezvous". A build that cannot honour that intent must not silently substitute
a different one. Falling back to the record path would hand a future descriptor's
payload to the A/TXT tokenizer, which is the wrong question answered confidently.
Refusing is visible: the name resolves to nothing and `name_rendezvous` reports
`"kind":"unsupported"` with the reason.

The cost of this choice is that a future v2 descriptor is unresolvable on a v1
build until it upgrades. That is the intended trade, and it is why the version
sits in the tag rather than being inferred from the body.

---

## 4. Resolver behaviour

### 4.1 The built-in DNS server refuses descriptors

`IDns::Search` fetches through `GetIDnsRecordValue`, which refuses the whole
descriptor family. `IDns::LocalSearch` applies the same rule to the local
override file.

A descriptor names an onion service. Plain DNS has no way to express that, and
there is no address to answer with, so the correct answer over UDP DNS is no
answer. The refusal covers valid and invalid descriptors alike, so an unknown
version cannot be answered as if it were an address record.

### 4.2 Dialing is SOCKS5 hostname CONNECT

`ConnectIDnsRendezvous` dials the service through a SOCKS5 proxy using an
`ATYP 0x03` (domain name) CONNECT. The hostname is handed to the proxy; the
client never resolves it and never holds an address for the service.

There is **no direct-connection fallback**. If the proxy is unreachable or
disabled, the dial fails. A failed rendezvous is never a clear-net connection.

The endpoint is `-idnssocks=<ip:port>`, default `127.0.0.1:9050`;
`-idnssocks=0` disables rendezvous dialing entirely.

`name_rendezvous <name> true` performs the dial and reports only whether it
succeeded, then closes the socket. It has no address to report either.

### 4.3 Why the default is an external tor, not the bundled one

The tree bundles a full Tor daemon (`src/tor`, started in-process by `StartTor`
with `--SocksPort 9089`). It is **Tor 0.3.0.9**:

- `hs_service.c` is a 172-line stub whose own comment says the functions are
  unused outside unit-test data generation;
- the 4,569-line `rendservice.c` is v2-only onion-service code;
- there is no `hs_client.c` at all — the v3 client landed in Tor 0.3.2.

v2 onion services were removed from the live Tor network in 2021. The bundled
daemon can therefore neither create nor visit a v3 onion service, however cleanly
it compiles. It is a working SOCKS proxy for ordinary traffic and nothing more.

The descriptor and resolver are consequently built against a *configurable* SOCKS5
endpoint. Point `-idnssocks` at an external tor ≥ 0.4.8 today. If the vendored
Tor is later upgraded, point it at `127.0.0.1:9089` and nothing else changes.

`CNetAddr::SetSpecial` is also v2-only (10-byte OnionCat mapping), so a 56-character
v3 hostname cannot be represented as a `CService` at all. This is why the dial
takes a hostname string and its own proxy endpoint rather than going through the
`NET_TOR` proxy tables — and it is a second, independent reason the address never
gets written down.

---

## 5. What is private and what is not

Private, structurally:

- **The service's IP address.** It appears in no name value, no name script, no
  transaction, no index record, no RPC output, and not in the bytes sent to the
  proxy. It cannot, because no code on this side ever learns it: a hostname
  CONNECT carries a name, and the rendezvous happens inside Tor.

Public, by design:

- **The name**, its **registration height** and its **expiry**. These are on-chain
  facts and have to be for a name system to work.
- **The onion hostname**. It is the pointer; it has to be readable to be usable.
  It identifies a Tor service, not a host or a network.
- **The holding address**, once the registration is mined. Ownership carries no
  key material in the operation itself (`a_name_operation_carries_no_owner_key_material`),
  and the index records none (`the_name_index_records_no_ownership`), but the
  destination in the output is public like any output.

Linkage between two names is exactly one thing: a reused destination. Every name
operation that does not name a destination now allocates through
`GetNameDestinationKey`, which refuses key reuse, so `name_new`, `name_update` and
`name_delete` each rotate the holding key and none can fall back to the wallet's
single default key.

---

## 6. Source map

| Piece | File |
| --- | --- |
| Grammar, classification, dial, RPC view | `src/idnsdescriptor.{h,cpp}` |
| SOCKS5 hostname CONNECT encoder and dial | `src/netbase.{h,cpp}` |
| DNS server dispatch | `src/idns.cpp` (`Search`, `LocalSearch`) |
| `name_rendezvous`, `name_rendezvous_encode` RPCs | `src/namecoin.cpp`, registered in `src/innovarpc.cpp` |
| Destination allocator | `src/namecoin.cpp` (`GetNameDestinationKey`) |
| Tests | `src/test/idns_rendezvous_tests.cpp` (`make check-idns-rendezvous`) |

---

## 7. Known gaps

1. **The bundled Tor cannot rendezvous.** Upgrading vendored Tor from 0.3.0.9 to
   a release with a v3 client (0.4.8.x) or replacing it with arti is a separate,
   scoped item: see `docs/architecture/TOR-VENDORED-UPGRADE-SCOPE.md`, which
   prices it against the seven defects four commits had to fix just to make
   0.3.0.9 compile on both platforms.
2. **No v3 checksum validation**, for want of SHA3-256 (section 2).
3. **No live rendezvous has been demonstrated** from this tree. The codec, the
   classification, the DNS refusal and the request encoding are covered by unit
   tests, and the registration path was driven end to end on a private regtest
   chain: `name_rendezvous_encode` -> `name_new` -> `name_show` returns the
   descriptor byte for byte and `name_rendezvous` classifies it, while the
   service address appears in none of `name_show`, `name_rendezvous`,
   `name_list`, `name_history` or `name_filter` for that name and does appear for
   an A-record control. What has *not* been run here is the last hop: an actual
   SOCKS5 connect through a real tor to a real onion service.
4. **No GUI surface.** `name_rendezvous_encode` builds a descriptor and
   `name_rendezvous <name> true` tests one, but neither is exposed in the Qt
   client.
5. **The default-key fallback is refused by construction, not by test.**
   `GetNameDestinationKey` passes `fAllowReuse=false`, so the branch that returns
   `vchDefaultKey` cannot be taken. No test can demonstrate that: reaching the
   branch needs an empty key pool, and an unlocked wallet always tops its pool up
   before reading it. The suite pins the allocator's observable contract -- N
   calls, N distinct destinations -- and the refusal itself is a code-read claim.
