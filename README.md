# SecChain VS Code Extension & CLI

This repository contains the **SecChain** security blockchain tool and its companion VS Code extension.

## Overview

**SecChain** is a lightweight, local blockchain implementation designed for system security monitoring. It tracks critical file changes and manages a local currency called "TrustyMCP".

The project consists of two main components:
1. **SecChain CLI (`secchain_cli.py`)**: A Python script that runs the blockchain, verifying integry and recording transactions.
2. **VS Code Extension**: An interface to interact with SecChain directly from your editor, featuring GitHub Copilot MCP integration.

## Features

- **Immutable Ledger**: Records file hashes and transactions in a local JSON blockchain.
- **System Monitoring**: Verifies the integrity of critical system files (e.g., `/etc/passwd`).
- **TrustyMCP Currency**: A proof-of-concept currency system built on the blockchain.
- **MCP Server**: Exposes blockchain tools to AI assistants (like GitHub Copilot) via the Model Context Protocol.

## Installation

### CLI Tool
The core logic is in `secchain_cli.py`. You can run it directly or install it to your path.
```bash
python3 secchain_cli.py --help
```

### VS Code Extension
1. Open this folder in VS Code.
2. Run `npm install` to install dependencies.
3. Press `F5` to launch the extension in debug mode.

## Usage

### CLI
- **Record new state**: `secchain record`
- **Verify integrity**: `secchain verify`
- **Check balance**: `secchain balance`

### Copilot MCP
Ask Copilot questions like:
- "Check my secchain balance"
- "Verify system integrity using secchain"

## License
MIT
