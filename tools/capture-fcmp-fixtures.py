#!/usr/bin/env python3
"""Record FCMP++ and Carrot responses from a regtest daemon into fixtures/fcmp.

No public network carries FCMP++ transactions that a CI run can reach, so the
fixtures come from a private regtest chain. Regtest runs the newest hard fork
from block 1, which makes every block after genesis an FCMP++ block and every
spend an FCMP++ spend. The shapes are the ones the stressnet produces: the same
serializer writes both.

Build monerod and monero-wallet-rpc from the FCMP++ branch, then start them:

    monerod --regtest --offline --fixed-difficulty 1 --non-interactive \\
        --data-dir /tmp/fcmp-regtest --rpc-bind-port 18081 \\
        --disable-dns-checkpoints --check-updates disabled
    monero-wallet-rpc --daemon-port 18081 --rpc-bind-port 18083 \\
        --disable-rpc-login --wallet-dir /tmp/fcmp-wallets \\
        --allow-mismatched-daemon-version

and run this:

    tools/capture-fcmp-fixtures.py --daemon http://127.0.0.1:18081 \\
        --wallet http://127.0.0.1:18083

The chain has to be fresh: the script mines its own history, and the heights
it records are only meaningful on a chain it built.
"""

import argparse
import json
import pathlib
import struct
import sys
import urllib.request

OUT = pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "fcmp"

# The seeds monerod's own functional tests use, so the addresses are public
# test addresses and nothing here is anyone's wallet.
SEEDS = [
    "velvet lymph giddy number token physics poetry unquoted nibs useful "
    "sabotage limits benches lifestyle eden nitrogen anvil fewest avoid batch "
    "vials washing fences goat unquoted",
    "peeled mixture ionic radar utopia puddle buying illness nuns gadget river "
    "spout cavernous bounced paradise drunk looking cottage jump tequila "
    "melting went winter adjust spout",
]


def post(url, body):
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=600) as r:
        return json.load(r)


def rpc(base, method, params=None):
    body = {"jsonrpc": "2.0", "id": "0", "method": method}
    if params is not None:
        body["params"] = params
    answer = post(base + "/json_rpc", body)
    if "error" in answer:
        sys.exit(f"{method}: {answer['error']}")
    return answer


def write(name, value):
    text = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    (OUT / f"{name}.json").write_text(text)
    print(f"  {name}.json  {len(text):>9,} bytes")


def open_wallet(wallet, name, seed):
    try:
        rpc(wallet, "close_wallet")
    except SystemExit:
        pass
    return rpc(wallet, "restore_deterministic_wallet", {
        "filename": name, "password": "", "seed": seed, "restore_height": 0,
    })["result"]["address"]


def epee_varint(n):
    """epee's varint: the low two bits give the width, 1, 2, 4 or 8 bytes."""
    for mark, fmt, limit in ((0, "<B", 1 << 6), (1, "<H", 1 << 14),
                             (2, "<I", 1 << 30), (3, "<Q", 1 << 62)):
        if n < limit:
            return struct.pack(fmt, (n << 2) | mark)
    raise ValueError(f"{n} has no epee varint")


def epee_request(as_of_n_blocks, unified_ids):
    """A /get_path_by_unified_id.bin request in epee's binary format."""
    out = struct.pack("<IIB", 0x01011101, 0x01020101, 1)
    out += epee_varint(2)
    name = b"as_of_n_blocks"
    out += bytes([len(name)]) + name + bytes([5]) + struct.pack("<Q", as_of_n_blocks)
    name = b"unified_ids"
    out += bytes([len(name)]) + name + bytes([5 | 0x80]) + epee_varint(len(unified_ids))
    out += b"".join(struct.pack("<Q", u) for u in unified_ids)
    return out


def epee_status_ok(body):
    """Whether a binary answer's root carries status "OK".

    The root entry is its name's length, the name, type 10 (a string), the
    string's varint length and the text, so this is a search for those bytes.
    """
    return b"\x06status\x0a" + epee_varint(2) + b"OK" in body


def post_bin(url, body):
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/octet-stream"})
    with urllib.request.urlopen(req, timeout=600) as r:
        return r.read()


def get_transactions(daemon, hashes, prune=False):
    return post(daemon + "/get_transactions", {
        "txs_hashes": hashes, "decode_as_json": True, "prune": prune,
        "split": True,
    })


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--daemon", default="http://127.0.0.1:18081")
    ap.add_argument("--wallet", default="http://127.0.0.1:18083")
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    d, w = args.daemon, args.wallet

    if rpc(d, "get_block_count")["result"]["count"] > 1:
        sys.exit("the chain is not fresh; start monerod on an empty data dir")

    recipient = open_wallet(w, "fcmp-recipient", SEEDS[1])
    miner = open_wallet(w, "fcmp-miner", SEEDS[0])

    # A coinbase unlocks after 60 blocks and an output enters the curve tree
    # when it unlocks, so the miner needs that long before it can spend
    # anything. Mining well past it gives the wallet a choice of inputs and
    # the tree more than one layer's worth of leaves.
    rpc(d, "generateblocks", {"amount_of_blocks": 120, "wallet_address": miner})
    rpc(w, "refresh")

    # Two transfers: one input paying one destination, and one paying three
    # destinations more than any single coinbase holds, so it has to spend two
    # inputs. An early regtest coinbase pays about 35 XMR.
    small = rpc(w, "transfer", {
        "destinations": [{"amount": 1_000_000_000_000, "address": recipient}],
    })["result"]["tx_hash"]
    wide = rpc(w, "transfer", {
        "destinations": [
            {"amount": 40_000_000_000_000, "address": recipient},
            {"amount": 20_000_000_000_000, "address": recipient},
            {"amount": 1_000_000_000_000, "address": miner},
        ],
    })["result"]["tx_hash"]

    print("before mining:")
    write("get_transaction_pool", post(d + "/get_transaction_pool", {}))
    write("get_transactions_pool", get_transactions(d, [small]))

    rpc(d, "generateblocks", {"amount_of_blocks": 1, "wallet_address": miner})
    tip = rpc(d, "get_last_block_header")
    height = tip["result"]["block_header"]["height"]

    print(f"after mining block {height}:")
    write("get_last_block_header", tip)
    block = rpc(d, "get_block", {"height": height})
    write("get_block_fcmp", block)
    coinbase_only = rpc(d, "get_block", {"height": height - 1})
    write("get_block_coinbase_only", coinbase_only)
    write("get_transactions_fcmp", get_transactions(d, [small, wide]))
    write("get_transactions_fcmp_pruned", get_transactions(d, [small], prune=True))
    write("get_transactions_coinbase",
          get_transactions(d, [block["result"]["miner_tx_hash"]]))
    # The tree size as of the small transaction's reference block, asked two
    # ways: probed with the transaction's own first output, which joins the
    # tree later and so costs no tree lookup, and with output 1, an early
    # coinbase already in the tree, whose answer carries a whole path.
    fetched = get_transactions(d, [small])["txs"][0]
    reference = json.loads(fetched["as_json"])["rctsig_prunable"]["reference_block"]
    for name, probe in (("probe_own_output", fetched["unified_ids"][0]),
                        ("probe_in_tree", 1)):
        body = post_bin(d + "/get_path_by_unified_id.bin",
                        epee_request(reference + 1, [probe]))
        if not epee_status_ok(body):
            sys.exit(f"get_path_by_unified_id.bin with probe {probe} did not "
                     "answer status OK")
        (OUT / f"get_path_by_unified_id_{name}.bin").write_bytes(body)
        print(f"  get_path_by_unified_id_{name}.bin  {len(body):>9,} bytes"
              f"  (as of block {reference}, probe {probe})")
    write("get_info", rpc(d, "get_info"))
    write("get_fee_estimate", rpc(d, "get_fee_estimate"))


if __name__ == "__main__":
    main()
