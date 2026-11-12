#!/usr/bin/env python3
"""Record curve-tree paths from a regtest daemon into fixtures/fcmp/paths.

The paths page hashes each path up to the tree's root and compares the result
with the root a block records, so its tests need paths and roots that monerod
itself produced. This builds a chain with more than 38 * 18 = 684 outputs in
the tree, which gives the tree three layers and so a root on the Selene curve
with a Helios layer below it: both of the tree's hashes are exercised.

Start monerod and monero-wallet-rpc as tools/capture-fcmp-fixtures.py
describes, on an empty data dir, and run this:

    tools/capture-path-fixtures.py --daemon http://127.0.0.1:18081 \\
        --wallet http://127.0.0.1:18083
"""

import argparse
import importlib.util
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE.parent / "fixtures" / "fcmp" / "paths"

_spec = importlib.util.spec_from_file_location(
    "capture_fcmp_fixtures", HERE / "capture-fcmp-fixtures.py")
fcmp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fcmp)

# How far a block's root runs behind the tree a path is taken from: the root
# for the tree as of tip B is the one block B - 8 records. TREE_ROOT_LAG in
# crates/monerod-rpc/src/types.rs.
TREE_ROOT_LAG = 8


def write(name, value):
    text = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    (OUT / f"{name}.json").write_text(text)
    print(f"  {name}.json  {len(text):>9,} bytes")


def paths(daemon, name, as_of_n_blocks, unified_ids):
    body = fcmp.post_bin(daemon + "/get_path_by_unified_id.bin",
                         fcmp.epee_request(as_of_n_blocks, unified_ids))
    if not fcmp.epee_status_ok(body):
        sys.exit(f"get_path_by_unified_id.bin for {unified_ids} did not "
                 "answer status OK")
    (OUT / f"{name}.bin").write_bytes(body)
    print(f"  {name}.bin  {len(body):>9,} bytes"
          f"  (as of block {as_of_n_blocks - 1}, ids {unified_ids})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--daemon", default="http://127.0.0.1:18081")
    ap.add_argument("--wallet", default="http://127.0.0.1:18083")
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    d, w = args.daemon, args.wallet
    rpc = fcmp.rpc

    if rpc(d, "get_block_count")["result"]["count"] > 1:
        sys.exit("the chain is not fresh; start monerod on an empty data dir")

    recipient = fcmp.open_wallet(w, "path-recipient", fcmp.SEEDS[1])
    miner = fcmp.open_wallet(w, "path-miner", fcmp.SEEDS[0])

    # One coinbase output a block, each joining the tree 60 blocks after it
    # is mined: 800 blocks put about 740 outputs in the tree.
    for _ in range(8):
        rpc(d, "generateblocks", {"amount_of_blocks": 100, "wallet_address": miner})
    rpc(w, "refresh")

    # Three destinations and the change: four outputs with consecutive ids.
    tx = rpc(w, "transfer", {
        "destinations": [
            {"amount": 3_000_000_000_000, "address": recipient},
            {"amount": 2_000_000_000_000, "address": recipient},
            {"amount": 1_000_000_000_000, "address": miner},
        ],
    })["result"]["tx_hash"]
    rpc(d, "generateblocks", {"amount_of_blocks": 1, "wallet_address": miner})

    print("after mining the transaction:")
    fetched = fcmp.get_transactions(d, [tx])
    write("get_transactions", fetched)
    ids = fetched["txs"][0]["unified_ids"]
    # Mined but not yet unlocked, so not yet in the tree: an empty path each.
    count = rpc(d, "get_block_count")["result"]["count"]
    paths(d, "get_path_by_unified_id_locked", count, ids)

    # Ten blocks later the outputs have unlocked and joined the tree.
    rpc(d, "generateblocks", {"amount_of_blocks": 10, "wallet_address": miner})
    count = rpc(d, "get_block_count")["result"]["count"]
    print(f"with the outputs in the tree, tip {count - 1}:")
    paths(d, "get_path_by_unified_id_tip", count, ids)
    write("get_block_root_tip", rpc(d, "get_block", {"height": count - 1 - TREE_ROOT_LAG}))
    # A few blocks later the tree has grown and the same outputs' paths have
    # changed at the tree's right edge, which is why a wallet keeps them
    # current rather than fetching them once.
    rpc(d, "generateblocks", {"amount_of_blocks": 3, "wallet_address": miner})
    count = rpc(d, "get_block_count")["result"]["count"]
    print(f"three blocks on, tip {count - 1}:")
    paths(d, "get_path_by_unified_id_later", count, ids)
    # Two early coinbase outputs, as of the same tree: full groups deep in the
    # tree rather than at its edge, in two different groups of leaves.
    paths(d, "get_path_by_unified_id_old", count, [10, 60])
    write("get_block_root_later", rpc(d, "get_block", {"height": count - 1 - TREE_ROOT_LAG}))


if __name__ == "__main__":
    main()
