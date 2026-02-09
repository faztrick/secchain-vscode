#!/usr/bin/env python3
# SecChain - Security Blockchain with TrustyMCP (TMCP) Currency
# Inspired by dvf/blockchain (MIT) and SignLedger (MIT)
# Pure Python, zero dependencies, stdlib only
import hashlib, json, os, subprocess, sys
from time import time
from datetime import datetime

CHAIN_DIR = os.path.join(os.getcwd(), "secchain_data")
CHAIN_FILE = os.path.join(CHAIN_DIR, "chain.json")
OWNER = "ffaz@kalifaz"
HOME = os.path.expanduser("~")

WATCHED = [
    "secchain_cli.py",
    "src/extension.ts",
    "mcp-server.py",
    "package.json",
    "README.md"
]

GENESIS_REWARD = 100
MINE_REWARD = 10
VERIFY_BONUS = 2
VIOLATION_PENALTY = 25
TAMPER_PENALTY = 5

TRUST = [(500,"DIAMOND"),(200,"PLATINUM"),(100,"GOLD"),
         (50,"SILVER"),(10,"BRONZE"),(0,"NEUTRAL"),(-999999,"COMPROMISED")]

def sha256(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()

def sha256_file(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return "MISSING"

def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, timeout=5).decode().strip()
    except Exception:
        return ""

def load_chain():
    if os.path.exists(CHAIN_FILE):
        with open(CHAIN_FILE) as f:
            return json.load(f)
    return []

def save_chain(chain):
    os.makedirs(CHAIN_DIR, exist_ok=True)
    with open(CHAIN_FILE, "w") as f:
        json.dump(chain, f, indent=2)

def collect_state():
    state = {}
    for p in WATCHED:
        state["file:" + p] = sha256_file(p)
    state["mcp_off"] = "1" if not run("pgrep -f mcp-server") else "0"
    state["ssh_off"] = "1" if not run("pgrep sshd") else "0"
    state["ufw_on"] = "1" if "active" in run("sudo ufw status 2>/dev/null || true") else "0"
    return state

def check_violations(state):
    v = []
    if state.get("mcp_off") != "1": v.append("MCP_PROCESS_DETECTED")
    if state.get("ssh_off") != "1": v.append("SSH_ACTIVE")
    if state.get("ufw_on") != "1": v.append("FIREWALL_INACTIVE")
    return v

def find_changes(chain, state):
    if not chain: return []
    last = chain[-1].get("state", {})
    return [k[5:] for k, v in state.items() if k.startswith("file:") and last.get(k, v) != v]

def get_balance(chain):
    return sum(tx.get("amount", 0) for b in chain for tx in b.get("transactions", []))

def get_trust(bal):
    for threshold, level in TRUST:
        if bal >= threshold: return level
    return "COMPROMISED"

def new_block(chain, state, txs, violations, changes):
    prev = chain[-1]["hash"] if chain else "0" * 64
    block = {"index": len(chain), "timestamp": time(), "prev_hash": prev,
             "state": state, "transactions": txs,
             "violations": violations, "changes": changes}
    block["hash"] = sha256(block)
    return block

def cmd_record(chain):
    state = collect_state()
    violations = check_violations(state)
    changes = find_changes(chain, state)
    txs = []
    if not chain:
        txs.append({"type": "GENESIS", "amount": GENESIS_REWARD, "note": "Genesis block"})
    txs.append({"type": "MINE", "amount": MINE_REWARD, "note": "Block mined"})
    for v in violations:
        txs.append({"type": "VIOLATION", "amount": -VIOLATION_PENALTY, "note": v})
    for c in changes:
        txs.append({"type": "TAMPER", "amount": -TAMPER_PENALTY, "note": c})
    block = new_block(chain, state, txs, violations, changes)
    chain.append(block)
    save_chain(chain)
    bal = get_balance(chain)
    dt = datetime.fromtimestamp(block["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
    print(f"Block #{block['index']} mined at {dt}")
    print(f"  Hash: {block['hash'][:16]}...")
    print(f"  Violations: {len(violations)} | Changes: {len(changes)}")
    print(f"  TMCP Balance: {bal} | Trust: {get_trust(bal)}")

def cmd_verify(chain):
    if not chain:
        print("No chain to verify"); return
    ok = True
    for i in range(1, len(chain)):
        b, p = dict(chain[i]), chain[i-1]
        if b["prev_hash"] != p["hash"]:
            print(f"BROKEN LINK at block #{i}"); ok = False
        stored = b.pop("hash")
        if stored != sha256(b):
            print(f"TAMPERED HASH at block #{i}"); ok = False
    txs = [{"type": "VERIFY", "amount": VERIFY_BONUS, "note": "Chain verified"}]
    block = new_block(chain, {}, txs, [], [])
    chain.append(block)
    save_chain(chain)
    bal = get_balance(chain)
    status = "VALID" if ok else "INVALID"
    print(f"Chain: {len(chain)} blocks | {status}")
    print(f"TMCP: {bal} | Trust: {get_trust(bal)}")

def cmd_status(chain):
    bal = get_balance(chain)
    print(f"SecChain Status for {OWNER}")
    print(f"  Blocks: {len(chain)}")
    print(f"  TMCP Balance: {bal}")
    print(f"  Trust Level: {get_trust(bal)}")
    if chain:
        last = chain[-1]
        dt = datetime.fromtimestamp(last["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
        print(f"  Last Block: #{last['index']} at {dt}")
        print(f"  Last Hash: {last['hash'][:32]}...")

def cmd_ledger(chain):
    for b in chain:
        for tx in b.get("transactions", []):
            s = "+" if tx["amount"] > 0 else ""
            print(f"  Block #{b['index']}: {s}{tx['amount']} TMCP [{tx['type']}] {tx['note']}")

def cmd_show(chain, n=5):
    for b in chain[-n:]:
        dt = datetime.fromtimestamp(b["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
        print(f"Block #{b['index']} | {dt} | {b['hash'][:16]}...")
        for tx in b.get("transactions", []):
            s = "+" if tx["amount"] > 0 else ""
            print(f"  {s}{tx['amount']} TMCP [{tx['type']}]")
        if b.get("violations"):
            vlist = ", ".join(b["violations"])
            print(f"  Violations: {vlist}")
        if b.get("changes"):
            clist = ", ".join(b["changes"])
            print(f"  Changed: {clist}")

USAGE = """SecChain - Security Blockchain with TrustyMCP (TMCP)
Inspired by dvf/blockchain & SignLedger (MIT)

Usage: secchain <command>
  record  - Record security state & mine block
  verify  - Verify chain integrity (+2 TMCP)
  status  - Show balance & trust level
  ledger  - Show all transactions
  show    - Show recent blocks
  export  - Export chain as JSON
  wallet  - (Coming Soon) Manage TMCP Wallet
  ui      - (Coming Soon) Launch CLI Dashboard
  market  - (Coming Soon) Trust Marketplace
  web     - (Coming Soon) Web Interface"""

def main():
    if len(sys.argv) < 2:
        print(USAGE); sys.exit(0)
    chain = load_chain()
    cmd = sys.argv[1]
    if cmd == "record": cmd_record(chain)
    elif cmd == "verify": cmd_verify(chain)
    elif cmd == "status": cmd_status(chain)
    elif cmd == "ledger": cmd_ledger(chain)
    elif cmd == "show":
        n = int(sys.argv[2]) if len(sys.argv) > 2 else 5
        cmd_show(chain, n)
    elif cmd == "export": print(json.dumps(chain, indent=2))
    elif cmd == "wallet": print("🚧 TMCP Wallet: Coming Soon! 🚧")
    elif cmd == "ui": print("🚧 CLI Dashboard: Coming Soon! 🚧")
    elif cmd == "market": print("🚧 Trust Market: Coming Soon! 🚧")
    elif cmd == "web": print("🚧 Web Interface: Coming Soon! 🚧")
    else: print(USAGE)

if __name__ == "__main__":
    main()
