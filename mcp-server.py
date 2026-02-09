#!/usr/bin/env python3
"""
SecChain MCP Server — Model Context Protocol server for Copilot integration.
Exposes SecChain blockchain tools so GitHub Copilot can query chain data,
verify integrity, and check TrustyMCP balance.
"""

import asyncio
import json
import hashlib
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# ── SecChain constants ────────────────────────────────────────────────
DIR = Path("/var/lib/secchain")
CHAIN = DIR / "chain.json"
SECCHAIN_BIN = "/usr/local/bin/secchain"

FILES = [
    "/home/ffaz/.config/Code - Insiders/User/settings.json",
    "/home/ffaz/.config/Code - Insiders/User/mcp.json",
    "/etc/hosts", "/etc/passwd", "/etc/sudoers",
    "/etc/sysctl.d/99-security.conf", "/usr/local/bin/watchdog.sh",
]

# ── Helpers ───────────────────────────────────────────────────────────
def load_chain() -> list[dict]:
    try:
        if not CHAIN.exists():
            return []
        return json.loads(CHAIN.read_text())
    except Exception:
        return []


def sha2(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def hash_file(f: str) -> str:
    try:
        return sha2(open(f, "rb").read())
    except Exception:
        return "MISSING"


def get_state() -> dict[str, str]:
    s = {f: hash_file(f) for f in FILES}
    checks = {
        "ufw": "sudo ufw status 2>/dev/null|head -1",
        "ssh": "systemctl is-active ssh 2>/dev/null",
        "ports": "ss -tlnp 2>/dev/null|grep -c LISTEN",
        "mcp": (
            "grep -c 'mcp.enabled.*true' "
            "'/home/ffaz/.config/Code - Insiders/User/settings.json' "
            "2>/dev/null || echo 0"
        ),
    }
    for k, c in checks.items():
        try:
            r = subprocess.run(c, shell=True, capture_output=True, text=True, timeout=5)
            s[k] = r.stdout.strip()
        except Exception:
            s[k] = "ERR"
    return s


def run_secchain(cmd: str) -> str:
    try:
        r = subprocess.run(
            ["sudo", SECCHAIN_BIN, cmd],
            capture_output=True, text=True, timeout=30
        )
        return r.stdout.strip() or r.stderr.strip()
    except Exception as e:
        return f"Error: {e}"


# ── MCP Server ────────────────────────────────────────────────────────
server = Server("secchain-mcp")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="secchain_balance",
            description=(
                "Get the current TrustyMCP cryptocurrency balance and chain stats. "
                "Returns balance, block count, and chain start date."
            ),
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="secchain_verify",
            description=(
                "Verify the integrity of the SecChain security blockchain. "
                "Checks all block hashes, chain links, and detects any tampering. "
                "Also reports live drift from the last recorded state."
            ),
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="secchain_show",
            description=(
                "Show all blocks in the SecChain blockchain. "
                "Returns block number, timestamp, TrustyMCP balance, and hash for each block."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "last_n": {
                        "type": "integer",
                        "description": "Only show the last N blocks. Omit for all blocks.",
                    }
                },
                "required": [],
            },
        ),
        Tool(
            name="secchain_record",
            description=(
                "Record a new security snapshot block on the SecChain blockchain. "
                "Captures file hashes, system checks (ufw, ssh, ports, mcp), and "
                "calculates TrustyMCP rewards/penalties. Requires sudo."
            ),
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="secchain_status",
            description=(
                "Get live security status of the system. Shows current state of "
                "monitored files and system checks, and compares against the last "
                "recorded block to detect drift/changes."
            ),
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="secchain_block",
            description=(
                "Get detailed information about a specific block by number."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "block_number": {
                        "type": "integer",
                        "description": "The block number to retrieve.",
                    }
                },
                "required": ["block_number"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "secchain_balance":
        chain = load_chain()
        if not chain:
            return [TextContent(type="text", text="No chain data. Run `sudo secchain record` to create genesis block.")]
        last = chain[-1]
        text = (
            f"TrustyMCP Balance: {last['tmcp']}\n"
            f"Blocks: {len(chain)}\n"
            f"Since: {chain[0]['t'][:10]}\n"
            f"Last block: #{last['n']} at {last['t'][:19]}\n"
            f"Last hash: {last['h'][:32]}…"
        )
        return [TextContent(type="text", text=text)]

    elif name == "secchain_verify":
        chain = load_chain()
        if not chain:
            return [TextContent(type="text", text="No chain to verify. Run `sudo secchain record` first.")]

        issues: list[str] = []
        for i, b in enumerate(chain):
            d = {"n": b["n"], "t": b["t"], "p": b["p"], "s": b["s"], "tmcp": b["tmcp"]}
            exp = sha2(json.dumps(d, sort_keys=True, separators=(",", ":")))
            if b["h"] != exp:
                issues.append(f"Block #{i} TAMPERED — hash mismatch!")
            if i > 0 and b["p"] != chain[i - 1]["h"]:
                issues.append(f"Block #{i} CHAIN BROKEN — prev_hash wrong!")

        # Live drift
        cur = get_state()
        last_s = chain[-1]["s"]
        drift = [k for k in cur if cur.get(k) != last_s.get(k)]

        if not issues and not drift:
            text = f"Chain VALID — {len(chain)} blocks, no tampering, no drift."
        else:
            parts = []
            if issues:
                parts.append("INTEGRITY ISSUES:\n" + "\n".join(f"  ⚠ {x}" for x in issues))
            else:
                parts.append(f"Chain integrity OK — {len(chain)} blocks.")
            if drift:
                parts.append("DRIFT DETECTED:\n" + "\n".join(f"  → {k}" for k in drift))
            text = "\n\n".join(parts)

        text += f"\n\nTrustyMCP Balance: {chain[-1]['tmcp']}"
        return [TextContent(type="text", text=text)]

    elif name == "secchain_show":
        chain = load_chain()
        if not chain:
            return [TextContent(type="text", text="Empty chain.")]
        last_n = arguments.get("last_n")
        blocks = chain[-last_n:] if last_n else chain
        lines = [f"#{b['n']} | {b['t'][:19]} | TMCP: {b['tmcp']} | {b['h'][:24]}…" for b in blocks]
        return [TextContent(type="text", text="\n".join(lines))]

    elif name == "secchain_record":
        result = run_secchain("record")
        return [TextContent(type="text", text=result)]

    elif name == "secchain_status":
        chain = load_chain()
        cur = get_state()

        parts: list[str] = ["=== Live Security Status ===\n"]

        # System checks
        parts.append(f"UFW:    {cur.get('ufw', '?')}")
        parts.append(f"SSH:    {cur.get('ssh', '?')}")
        parts.append(f"Ports:  {cur.get('ports', '?')}")
        parts.append(f"MCP:    {cur.get('mcp', '?')}")
        parts.append("")

        # File integrity
        parts.append("=== Monitored Files ===")
        for f in FILES:
            short = f.split("/")[-1]
            h = cur.get(f, "?")
            status = "OK"
            if chain:
                old_h = chain[-1]["s"].get(f)
                if old_h and old_h != h:
                    status = "CHANGED"
                elif h == "MISSING":
                    status = "MISSING"
            parts.append(f"  {short}: {status} ({h[:16]}…)")

        if chain:
            parts.append(f"\nTrustyMCP: {chain[-1]['tmcp']}")
            parts.append(f"Blocks: {len(chain)}")

        return [TextContent(type="text", text="\n".join(parts))]

    elif name == "secchain_block":
        chain = load_chain()
        bn = arguments.get("block_number", 0)
        if bn < 0 or bn >= len(chain):
            return [TextContent(type="text", text=f"Block #{bn} not found. Chain has {len(chain)} blocks (0-{len(chain)-1}).")]
        b = chain[bn]
        text = json.dumps(b, indent=2)
        return [TextContent(type="text", text=f"Block #{bn} details:\n{text}")]

    return [TextContent(type="text", text=f"Unknown tool: {name}")]


# ── Main ──────────────────────────────────────────────────────────────
async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
