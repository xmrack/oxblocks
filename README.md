# oxblocks

Oxide Blocks (oxblocks) is a Monero block explorer written in Rust.

The explorer does not open the blockchain database. It holds no keys. It writes
nothing to disk. For each request it asks the daemon over RPC and renders the answer.

The JSON API serves the same response bodies as
[xmrblocks](https://github.com/moneroexamples/onion-monero-blockchain-explorer),
so a client that reads the body works without changes. It differs on two
points, both listed under [JSON API](#json-api).

## Requirements

* A `monerod` node with **unrestricted** RPC. A restricted daemon blocks the
  calls behind the mempool and alt-chain pages.
* Rust 1.88 or later, to build from source. Use Docker instead if you prefer.

Point the explorer at a local daemon such as `http://127.0.0.1:18081`. Do not
point it at a public restricted port.

Pruned nodes work. Read [Pruned nodes](#pruned-nodes) for the one field that
differs.

## Build and run

```bash
git clone https://github.com/xmrack/oxblocks
cd oxblocks
cargo build --release
./target/release/oxblocks --daemon-url http://127.0.0.1:18081
```

The explorer listens on `127.0.0.1:8081`. Open `http://127.0.0.1:8081/` in a
browser.

To serve other machines, bind to an address they can reach:

```bash
./target/release/oxblocks --bind 0.0.0.0:8081 --daemon-url http://127.0.0.1:18081
```

### Options

Each option also reads an environment variable. The command line wins.

| Option | Variable | Default | Purpose |
| --- | --- | --- | --- |
| `--daemon-url` | `OXBLOCKS_DAEMON_URL` | `http://127.0.0.1:18081` | The monerod RPC address. |
| `--bind` | `OXBLOCKS_BIND` | `127.0.0.1:8081` | The address to listen on. |
| `--theme` | `OXBLOCKS_THEME` | `auto` | Colour scheme. Use `auto`, `light` or `dark`. |
| `--rpc-timeout-secs` | `OXBLOCKS_RPC_TIMEOUT` | `30` | Limit for one RPC call. |
| `--request-timeout-secs` | `OXBLOCKS_REQUEST_TIMEOUT` | `25` | Limit for one inbound request. |
| `--max-concurrent` | `OXBLOCKS_MAX_CONCURRENT` | `128` | Requests handled at the same time, across all routes. A request waits for a slot within its timeout. |
| `--max-inflight-rpc` | `OXBLOCKS_MAX_INFLIGHT_RPC` | `16` | RPC calls open at the same time. Keep it under monerod's `--rpc-max-connections-per-private-ip` (25), or `-per-public-ip` (3) for a daemon reached over a public address. |
| `--max-body-bytes` | `OXBLOCKS_MAX_BODY` | `8192` | Largest accepted request body. |
| `--max-response-mib` | `OXBLOCKS_MAX_RESPONSE_MIB` | `256` | Largest answer accepted from monerod, in MiB. Lower it for a node you do not run. |
| `--postfix-min` | `OXBLOCKS_POSTFIX_MIN` | `2` | Shortest postfix the private lookup accepts. |
| `--postfix-max` | `OXBLOCKS_POSTFIX_MAX` | `12` | Longest postfix the private lookup accepts. |
| `--max-block-range` | `OXBLOCKS_MAX_BLOCK_RANGE` | `100` | Most blocks `/api/blocks` serves at once. |
| `--recent-blocks` | `OXBLOCKS_RECENT_BLOCKS` | `30` | How far back `/api/transactions/recent` reaches. |
| `--log` | `OXBLOCKS_LOG` | `info` | Log filter, such as `oxblocks=debug`. |

Run `oxblocks --help` for the full text of each option.

## Run in Docker

```bash
docker build -t oxblocks .
docker run --rm -p 127.0.0.1:8081:8081 \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --memory 1g --pids-limit 128 \
  oxblocks --bind 0.0.0.0:8081 --daemon-url http://DAEMON-HOST:18081
```

The image is distroless. It runs as the `nonroot` user. It holds one binary and
has no shell and no package manager. The stylesheet is compiled into the binary,
so you do not need to mount an asset directory. It writes nothing, needs no
capabilities, and runs under the same memory limit as the systemd unit.

Publish the port on `127.0.0.1` for a reverse proxy on the same host. A bare
`-p 8081:8081` listens on every interface, and Docker's own firewall rules let
it past the host's firewall.

Bind to `0.0.0.0` inside the container. The default of `127.0.0.1` is not
reachable from outside it.

To reach a daemon on the Docker host:

* **Linux.** Share the host network instead of publishing a port:

  ```bash
  docker run --rm --network host \
    --read-only --cap-drop ALL --security-opt no-new-privileges \
    --memory 1g --pids-limit 128 \
    oxblocks --bind 127.0.0.1:8081 --daemon-url http://127.0.0.1:18081
  ```

* **Docker Desktop.** Keep `-p 8081:8081` and use
  `--daemon-url http://host.docker.internal:18081`.

## Run as a service

`deploy/oxblocks.service` is a hardened systemd unit.

```bash
sudo install -m755 target/release/oxblocks /usr/local/bin/oxblocks
sudo install -m644 deploy/oxblocks.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now oxblocks
```

The unit runs the explorer under a dynamic user with no capabilities, a
read-only filesystem, no writable paths, no executable memory, and a syscall
filter. It sees no other user and allows IPv4 and IPv6 sockets to localhost
only. Widen `IPAddressAllow` only to the hosts that your daemon and proxy use. It
may listen on port 8081 alone: if you change `--bind`, change `SocketBindAllow`
to match.

Put a TLS reverse proxy in front of the explorer. oxblocks serves plain HTTP.

## Web interface

| Path | Page |
| --- | --- |
| `/` and `/page/<n>` | Recent blocks. |
| `/block/<height or hash>` | One block and the transactions in it. |
| `/tx/<hash>` | One transaction, with inputs, outputs and ring member ages. |
| `/tx/<hash>/paths` | Where the transaction's outputs sit in the FCMP++ curve tree, one output or all of them. |
| `/mempool` | Transactions that wait to be mined. Click a column heading to sort. |
| `/altblocks` | Alternative chains that the daemon knows about. |
| `/search?q=` | Find a block or a transaction. |
| `/api` | API documentation for this deployment. |
| `/health` | Liveness and cache counters, as JSON. |

The server renders every page. There is no JavaScript, no cookie, no image, no
web font and no external request. One stylesheet ships inside the binary.

`--theme auto` follows the light or dark setting of each reader. `--theme light`
and `--theme dark` fix one palette for everyone.

## JSON API

Every response is wrapped. Keys are sorted alphabetically.

```json
{"data": { ... }, "status": "success"}
{"data": {"title": "Cant parse tx hash: deadbeef"}, "status": "fail"}
{"data": null, "message": "...", "status": "error"}
```

`fail` means the caller asked for something this explorer will not answer.
`error` means the explorer or its daemon could not answer.

The HTTP status says the same thing.

| Code | Meaning |
| --- | --- |
| 200 | The answer is in `data`. |
| 400 | The argument is not one this explorer reads, or a limit is over its cap. |
| 404 | The argument was well formed and the chain does not hold it. |
| 500 | A bug here. |
| 502 | The daemon could not be reached, or answered with something unusable. |
| 503 | This deployment cannot serve the endpoint, because of how its daemon is built or configured. |

Arguments are read as given. A height is decimal digits, a hash is 64 hex
characters of either case, and a postfix is hex. Anything else is a 400, and so
is a `page` or `limit` that is not a plain number.

Those two points are where the API departs from xmrblocks, which answers 200 to
everything and deletes the characters it does not recognise before it parses.

| Endpoint | Returns |
| --- | --- |
| `/api/block/<height or hash>` | One block with its transactions. |
| `/api/transaction/<hash>` | One transaction, with rings expanded. |
| `/api/transaction/<hash>/paths?block=&from=&output=` | The curve-tree paths of up to 50 of the transaction's outputs, or of one, checked. |
| `/api/rawblock/<height or hash>` | The block as the daemon holds it. |
| `/api/rawtransaction/<hash>` | The transaction as the daemon holds it. |
| `/api/transactions?page=&limit=` | Transactions by block, newest first. `limit` is at most 50. |
| `/api/mempool?page=&limit=` | Transactions in the mempool. `limit` is at most 500. |
| `/api/search/<height or hash>` | A block or a transaction, whichever matches. |
| `/api/networkinfo` | Height, difficulty, hash rate and peer counts. |
| `/api/feeestimate?grace_blocks=` | The current fee per byte. |
| `/api/version` | The explorer version and the daemon version. |
| `/api/blocks/<start>/<end>` | A range of blocks. 100 blocks at most. |
| `/api/transaction/private/<postfix>` | Every transaction whose hash ends with the postfix. |
| `/api/transactions/recent` | The mempool plus the last 30 blocks, the same window for every caller. |

A running explorer documents its own API at `/api`. That page lists each
parameter and each limit. It also states two facts that no static page can
state: which postfix lengths this chain accepts now, and whether this daemon can
serve the private lookup at all.

Endpoints that need a view key, a secret or raw transaction hex do not exist
here. Neither does an emission total, because that needs a full chain scan and
this explorer keeps no index.

### Private lookups and k-anonymity

Three endpoints let a caller fetch data without a request that singles out what
it wants.

`/api/transaction/private/<postfix>` returns every transaction whose hash ends
with the hex postfix that you give. The caller picks the one it wants on its
own machine, and the explorer cannot tell which one that was.
`/api/blocks/<start>/<end>` does the same for blocks. Ask for a range and keep
the block you meant.

`/api/transactions/recent` works differently: there is nothing to pick, because
every caller who hits it gets the same window, the unconfirmed pool plus the
last 30 blocks (`--recent-blocks`). A request for "the newest transaction"
would otherwise name that transaction. A request for "whatever is recent" does
not, because it is the same request no matter who sends it or which transaction
they actually want.

A postfix is 2 to 12 hex characters (`--postfix-min`, `--postfix-max`). The
explorer also checks the postfix against the size of the chain, and accepts it
only when it expects 20 to 1000 matches. Both of those bounds count
transactions, not characters, so the lengths that qualify change as the chain
grows. On mainnet today, 5 characters qualify.

The lower bound is the privacy rule. Each added character divides the expected
set by 16. Real match counts vary around the expected count, so a small set
often returns one transaction and hides nothing.

The upper bound protects the daemon. The daemon walks its whole transaction
index to answer, and a short postfix makes it return hundreds of thousands of
hashes. The explorer refuses that before it makes the call.

`/api/blocks` serves 100 blocks at most (`--max-block-range`), because each
block costs two RPC calls. The refusal is arithmetic on the two heights, so an
over-wide range costs the daemon nothing.

Every one of these four bounds trades how well a caller hides against what the
request costs. Widening one widens both. A running explorer reports the bounds
it was started with on its `/api` page, so they can be read rather than
guessed.

This lookup needs a daemon that has `get_txids_loose`. A daemon without it
answers `Method not found`, and this one endpoint returns that as its error.
Every other endpoint works either way.

## FCMP++ and Carrot

oxblocks supports hard fork 17, FCMP++ and Carrot, in the format of monerod's
`fcmp++-beta-stressnet-v3` branch, and reads the chain on both sides of the
fork.

The beta stressnet runs on testnet. Start its monerod with `--testnet` and point
oxblocks at `http://127.0.0.1:28081`.

For an FCMP++ transaction, RingCT type 7, the transaction page shows the
anonymity set, which is the size of the curve tree as of the transaction's
reference block, and draws that tree layer by layer. It also shows the
reference block, the tree's layer count and the proof size. Inputs have no
ring. Carrot outputs show their 3-byte view tag and encrypted Janus anchor, and
every mined output shows its unified ID, which a daemon with FCMP++ reports.
Blocks from the fork on show their curve tree root and layer count.

The JSON API carries the same data in these keys, each `null` where it does
not apply:

| Key | Object |
| --- | --- |
| `reference_block`, `n_tree_layers`, `fcmp_pp_proof_size` | transaction |
| `anonymity_set` | transaction, from `/api/transaction` and `/api/search` |
| `view_tag`, `encrypted_janus_anchor`, `unified_id` | output |
| `tree_root`, `n_tree_layers` | block |

An FCMP++ transaction reports `mixin` 0, and each input's `mixins` is `[]`. On a
pruned node, a transaction whose prunable data is gone has no reference block,
layer count, proof size or anonymity set.

The tree size comes from `/get_path_by_unified_id.bin`, monerod's binary RPC,
which oxblocks decodes itself. `fixtures/fcmp/` holds responses recorded from a
regtest daemon on the stressnet branch, and `tools/capture-fcmp-fixtures.py`
records them again.

### Curve tree paths

`/tx/<hash>/paths` shows each mined output's path through the curve tree, as of
the tip or of a block given as `?block=`. A path is what a wallet holds to
spend the output: the group of up to 38 outputs it sits in, then at each layer
above, the group of up to 18 or 38 nodes holding its ancestor, up to the root.
The page shows one output's path, or all of a transaction's paths together
with the groups they share, and says what a wallet would store for them. It
draws the part of the tree the paths climb through as a grid: each row is a
group of outputs and ends in the layer-1 node it hashes to, and each layer
above is a column of its group, bracketed to the node it hashes to, up to
the root.

The same endpoint gives the paths. oxblocks asks for up to 50 outputs a call,
the most a restricted node answers. It first checks that the leaf each path
climbs from is the output: its key, and its commitment where the transaction
records one, are the transaction's. It then recomputes every hash from the
leaves up: it derives each leaf from the output's key and commitment, hashes
each group on its curve, and checks that each hash is the member of the layer
above that the path names. The last hash must be the root recorded by the
block eight below the one asked about. The hash, its generators, the curves
and the hash-to-point functions are monero-oxide's, at the revision monerod's
stressnet branch links; the generators are loaded once at startup. The hashing
runs off the request threads, four answers at a time, and a group shared by
several outputs is hashed once.

oxblocks also takes its reading of monerod's binary answers from monero-oxide
(`monero-epee`), and the FCMP++ proof's layout (`Fcmp::ipa_rows`,
`Fcmp::proof_size`).

An output joins the tree in the block nine after the one that mined it by
default, the last before it can be spent, so a transaction's outputs have no
path before then. The page says
which block they join as of. `tools/capture-path-fixtures.py` records the
paths and roots in `fixtures/fcmp/paths/`, which the tests hash up to the
roots monerod recorded.

## Architecture

```
┌──────────────┐   HTTP/JSON   ┌──────────────┐   LMDB   ┌──────────┐
│   oxblocks   │ ────────────> │   monerod    │ ───────> │ data.mdb │
└──────────────┘      RPC      └──────────────┘          └──────────┘
```

| Crate | Role |
| --- | --- |
| `monerod-rpc` | Typed async RPC client. The only crate that touches the network. |
| `explorer-core` | Domain types, chain access, `tx_extra` decoding, caching. |
| `explorer-web` | Routes, templates and the JSON API. Builds the `oxblocks` binary. |

The compiler holds the split in place. `explorer-core` cannot use the web
framework, and `monerod-rpc` cannot use either of the other two crates.

The process keeps one thing in memory: a bounded cache. It caches an object
named by hash at once, because a hash names one object forever. It caches an
object named by height only when that height is more than 60 blocks deep,
because a reorg gives a height to a different block. The same holds for an
output's path through the curve tree: one is kept once it has been checked up
to the root its block records, and only as of a block that deep. Losing the
cache costs speed, not correctness. `/health` reports the size and the hit counts.

## Security design

**No unsafe code.** Every crate in this repository sets
`#![forbid(unsafe_code)]`, and the compiler enforces it. This covers the code
here. It does not cover the dependency tree, where some crates do use `unsafe`.
`tools/check-unsafe.sh` fails the build when a crate stops inheriting the rule.

**Escaped output.** Templates escape every value at compile time. To emit a raw
value a developer must write `|safe`.

**A strict browser policy.** Every response carries
`Content-Security-Policy: default-src 'none'; style-src 'self'; form-action
'self'; base-uri 'none'; frame-ancestors 'none'`, plus `nosniff`,
`Referrer-Policy: no-referrer` and `X-Frame-Options: DENY`. The middleware adds
these headers outside the router, so a timeout or a rejected body carries them
too.

**Backpressure.** Each page costs RPC calls, so a traffic spike could otherwise
overload the daemon. The explorer caps the requests it handles at once and the
RPC calls it opens at once. It also gives every inbound request a deadline that
is shorter than the RPC deadline.

**Checked arithmetic.** Release builds keep `overflow-checks` on. Chain values
are 64-bit integers, and a silent wrap would put a wrong number on a page.

**A controlled dependency tree.** `deps-baseline.txt` lists every third-party
crate, and `tools/check-deps.sh` fails the build when a crate enters or leaves
without an update to that file. `cargo deny` runs in CI over advisories,
licences, duplicate versions and source registries. Read the tree yourself with
`cargo tree --workspace -e normal`.

## Pruned nodes

On a pruned daemon, `tx_size` under-reports for a transaction outside the stripe
that the node keeps. The node holds only the prefix, so the missing bytes are
not there to count. Run an unpruned daemon if you need that field to be exact.
Every other field is correct on a pruned node, because ring expansion reads the
output table, and the daemon never prunes that table.

## Testing

```bash
cargo test --workspace
```

That needs no node, because `fixtures/` holds captured RPC responses to replay.
Four layers cover the code:

1. Unit tests in each crate.
2. Fixture replay of real RPC responses.
3. Differential tests that compare the `/api/*` output against captured
   xmrblocks output from the same chain.
4. `tools/txextra-oracle`, which compares the `tx_extra` parser against a C++
   oracle on random input. Run it by hand, not in CI.

Live tests need a node and stay off by default:

```bash
OXBLOCKS_TEST_RPC=http://127.0.0.1:28081 cargo test -- --ignored
```

## License

MIT. Read [LICENSE](LICENSE).
