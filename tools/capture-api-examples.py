#!/usr/bin/env python3
"""Record the example responses shown on the /api documentation page.

The page shows real recorded answers rather than invented ones, so the hashes
and amounts a reader sees are the ones the chain holds. Re-run this against an
explorer when a response shape changes:

    tools/capture-api-examples.py --base http://127.0.0.1:8090 \
        --recent-base http://127.0.0.1:8092

The recordings come from explorers reading a regtest chain run by
monerod's FCMP++ branch (see tools/capture-fcmp-fixtures.py), so they show
FCMP++ transactions. The chain needs at least 405 blocks, two adjacent ones
carrying one to four transactions each, and one transaction in the pool.

Two endpoints cannot be recorded straight and are noted where they are built.
"""

import argparse
import json
import pathlib
import sys
import urllib.request

OUT = pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "api-examples"


def fetch(base, path):
    with urllib.request.urlopen(base + path, timeout=60) as r:
        return json.load(r)


def write(name, value):
    text = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    (OUT / f"{name}.json").write_text(text)
    print(f"  {name}.json  {len(text):>7,} bytes")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8090")
    ap.add_argument("--recent-base", default=None,
                    help="an explorer started with --recent-blocks 1, so the "
                         "recorded window is one block rather than thirty")
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)

    tip = fetch(args.base, "/api/networkinfo")["data"]["height"]
    # Two adjacent blocks that each carry a couple of transactions. Every
    # shape below is the same on a busy block, and a 200-transaction one
    # documents it no better while taking fifty times the room.
    height = None
    previous = None
    for h in range(tip - 400, tip - 5):
        txs = fetch(args.base, f"/api/block/{h}")["data"]["txs"]
        if not 1 <= len(txs) - 1 <= 4:
            previous = None
            continue
        if previous == h - 1:
            height = h
            break
        previous = h
    if height is None:
        sys.exit("no pair of compact blocks found near the tip")
    block = fetch(args.base, f"/api/block/{height}")["data"]
    tx_hash = block["txs"][1]["tx_hash"]
    print(f"recording from block {height}, transaction {tx_hash[:16]}...")

    write("version", fetch(args.base, "/api/version"))
    write("networkinfo", fetch(args.base, "/api/networkinfo"))
    write("feeestimate", fetch(args.base, "/api/feeestimate"))
    write("health", fetch(args.base, "/health"))
    write("block", fetch(args.base, f"/api/block/{height}"))
    write("blocks_range", fetch(args.base, f"/api/blocks/{height - 1}/{height}"))
    transaction = fetch(args.base, f"/api/transaction/{tx_hash}")
    write("transaction", transaction)
    # Page 0 is the tip, which is whatever size the chain is busy with.
    # Counting back to the compact block above keeps the example small and
    # leaves it a real answer.
    page = (tip - 1) - height
    write("transactions",
          fetch(args.base, f"/api/transactions?page={page}&limit=1"))
    write("mempool", fetch(args.base, "/api/mempool?limit=1"))
    write("search_block", fetch(args.base, f"/api/search/{height}"))
    write("search_tx", fetch(args.base, f"/api/search/{tx_hash}"))

    # /api/transaction/private needs a daemon with get_txids_loose, which no
    # released monerod has, and a chain big enough for its postfix bounds. The
    # endpoint answers the transactions whose hash ends with the postfix and
    # leaves their rings unresolved, so the recorded answer is the real
    # transaction above with the field the endpoint does not fill set to null.
    # An FCMP++ input has no ring to leave unresolved and keeps its []. The
    # tree size is filled only by /api/transaction and a search that lands on
    # it, so it is null here too.
    private = json.loads(json.dumps(transaction["data"]))
    private["anonymity_set"] = None
    if private.get("rct_type") != 7:
        for i in private.get("inputs") or []:
            i["mixins"] = None
    write("transaction_private", {"data": {"missed_txs": [], "txs": [private],
                                           "txs_no": 1},
                                  "status": "success"})

    # /api/transactions/recent takes no parameters and bounds only its block
    # window, so it answers the whole pool beside it, which can run to hundreds
    # of kilobytes and documents nothing the first two entries do not. Record a
    # one-block window and keep one transaction from the pool and one from the
    # block, with the pool count corrected to match what is left. Every value
    # below is still the chain's own.
    recent = fetch(args.recent_base or args.base, "/api/transactions/recent")
    txs = recent["data"]["txs"]
    pool = [t for t in txs if t["block_height"] == 0][:1]
    mined = [t for t in txs if t["block_height"] != 0][:1]
    recent["data"]["txs"] = pool + mined
    recent["data"]["mempool_txs_no"] = len(pool)
    write("transactions_recent", recent)


if __name__ == "__main__":
    main()
