import * as vscode from 'vscode';
import { execFile } from 'child_process';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

// ── SecChain data types ──────────────────────────────────────────────
interface Block {
    n: number;
    t: string;
    p: string;
    sh: string;
    s: Record<string, string>;
    tmcp: number;
    h: string;
}

const CHAIN_PATH = '/var/lib/secchain/chain.json';
const SECCHAIN_BIN = '/usr/local/bin/secchain';

// ── Helpers ──────────────────────────────────────────────────────────
function loadChain(): Block[] {
    try {
        if (!existsSync(CHAIN_PATH)) { return []; }
        return JSON.parse(readFileSync(CHAIN_PATH, 'utf-8'));
    } catch {
        return [];
    }
}

function runSecChain(cmd: string): Promise<string> {
    return new Promise((resolve, reject) => {
        execFile('sudo', [SECCHAIN_BIN, cmd], { timeout: 30000 }, (err, stdout, stderr) => {
            if (err) { reject(new Error(stderr || err.message)); }
            else { resolve(stdout.trim()); }
        });
    });
}

// ── Status bar ───────────────────────────────────────────────────────
let statusBar: vscode.StatusBarItem;

function updateStatusBar() {
    const chain = loadChain();
    if (chain.length === 0) {
        statusBar.text = '$(shield) SecChain: No chain';
        statusBar.tooltip = 'Run SecChain Record to create genesis block';
    } else {
        const last = chain[chain.length - 1];
        statusBar.text = `$(shield) TMCP: ${last.tmcp} | #${last.n}`;
        statusBar.tooltip = `TrustyMCP Balance: ${last.tmcp}\nBlocks: ${chain.length}\nLast: ${last.t.slice(0, 19)}\nHash: ${last.h.slice(0, 24)}…`;
    }
    statusBar.show();
}

// ── Tree view: Blockchain Explorer ───────────────────────────────────
class BlockItem extends vscode.TreeItem {
    constructor(public readonly block: Block) {
        super(
            `#${block.n} ${block.n === 0 ? 'GENESIS' : ''} — TMCP: ${block.tmcp}`,
            vscode.TreeItemCollapsibleState.Collapsed
        );
        this.description = block.t.slice(0, 19);
        this.tooltip = `Hash: ${block.h}\nPrev: ${block.p.slice(0, 24)}…`;
        this.iconPath = new vscode.ThemeIcon(block.n === 0 ? 'star-full' : 'git-commit');
        this.contextValue = 'block';
    }
}

class BlockDetailItem extends vscode.TreeItem {
    constructor(label: string, value: string) {
        super(`${label}: ${value}`, vscode.TreeItemCollapsibleState.None);
        this.tooltip = value;
        this.iconPath = new vscode.ThemeIcon('info');
    }
}

class ChainTreeProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
    private _onDidChange = new vscode.EventEmitter<void>();
    readonly onDidChangeTreeData = this._onDidChange.event;

    refresh() { this._onDidChange.fire(); }

    getTreeItem(el: vscode.TreeItem) { return el; }

    getChildren(el?: vscode.TreeItem): vscode.TreeItem[] {
        if (!el) {
            const chain = loadChain();
            return chain.map(b => new BlockItem(b)).reverse();
        }
        if (el instanceof BlockItem) {
            const b = el.block;
            const items: vscode.TreeItem[] = [
                new BlockDetailItem('Hash', b.h.slice(0, 32) + '…'),
                new BlockDetailItem('Time', b.t.slice(0, 19)),
                new BlockDetailItem('TMCP', String(b.tmcp)),
            ];
            // show watched file statuses
            const fileKeys = Object.keys(b.s).filter(k => k.startsWith('/'));
            const checkKeys = Object.keys(b.s).filter(k => !k.startsWith('/'));
            if (fileKeys.length) {
                items.push(new BlockDetailItem('Files', `${fileKeys.length} monitored`));
            }
            for (const k of checkKeys) {
                items.push(new BlockDetailItem(k, b.s[k]));
            }
            return items;
        }
        return [];
    }
}

// ── Tree view: Security Status ───────────────────────────────────────
class StatusTreeProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
    private _onDidChange = new vscode.EventEmitter<void>();
    readonly onDidChangeTreeData = this._onDidChange.event;

    refresh() { this._onDidChange.fire(); }

    getTreeItem(el: vscode.TreeItem) { return el; }

    getChildren(): vscode.TreeItem[] {
        const chain = loadChain();
        if (chain.length === 0) {
            const item = new vscode.TreeItem('No chain data — run Record first');
            item.iconPath = new vscode.ThemeIcon('warning');
            return [item];
        }
        const last = chain[chain.length - 1];
        const items: vscode.TreeItem[] = [];

        // Balance
        const bal = new vscode.TreeItem(`TrustyMCP Balance: ${last.tmcp}`);
        bal.iconPath = new vscode.ThemeIcon(last.tmcp >= 100 ? 'pass' : last.tmcp >= 0 ? 'warning' : 'error');
        items.push(bal);

        // Chain length
        const len = new vscode.TreeItem(`Chain Length: ${chain.length} blocks`);
        len.iconPath = new vscode.ThemeIcon('link');
        items.push(len);

        // System checks
        const ufw = new vscode.TreeItem(`UFW: ${last.s['ufw'] || 'unknown'}`);
        ufw.iconPath = new vscode.ThemeIcon(last.s['ufw']?.includes('active') ? 'pass' : 'error');
        items.push(ufw);

        const ssh = new vscode.TreeItem(`SSH: ${last.s['ssh'] || 'unknown'}`);
        ssh.iconPath = new vscode.ThemeIcon(last.s['ssh'] === 'inactive' ? 'pass' : 'warning');
        items.push(ssh);

        const ports = new vscode.TreeItem(`Open Ports: ${last.s['ports'] || '?'}`);
        ports.iconPath = new vscode.ThemeIcon('globe');
        items.push(ports);

        // Last hash
        const hash = new vscode.TreeItem(`Last Hash: ${last.h.slice(0, 24)}…`);
        hash.iconPath = new vscode.ThemeIcon('key');
        items.push(hash);

        return items;
    }
}

// ── Output channel ───────────────────────────────────────────────────
let output: vscode.OutputChannel;

function showOutput(title: string, text: string) {
    output.clear();
    output.appendLine(`═══ ${title} ═══`);
    output.appendLine(text);
    output.show(true);
}

// ── Extension activation ─────────────────────────────────────────────
export function activate(context: vscode.ExtensionContext) {
    output = vscode.window.createOutputChannel('SecChain');

    // Status bar
    statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
    statusBar.command = 'secchain.balance';
    updateStatusBar();
    context.subscriptions.push(statusBar);

    // Tree views
    const chainTree = new ChainTreeProvider();
    const statusTree = new StatusTreeProvider();
    vscode.window.registerTreeDataProvider('secchain.chainView', chainTree);
    vscode.window.registerTreeDataProvider('secchain.statusView', statusTree);

    function refreshAll() {
        updateStatusBar();
        chainTree.refresh();
        statusTree.refresh();
    }

    // ── Commands ─────────────────────────────────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand('secchain.record', async () => {
            try {
                const result = await runSecChain('record');
                showOutput('Record', result);
                vscode.window.showInformationMessage(`SecChain: ${result.split('\n')[0]}`);
                refreshAll();
            } catch (e: any) {
                vscode.window.showErrorMessage(`SecChain Record failed: ${e.message}`);
            }
        }),

        vscode.commands.registerCommand('secchain.verify', async () => {
            try {
                const result = await runSecChain('verify');
                showOutput('Verify', result);
                const valid = result.includes('VALID');
                if (valid) {
                    vscode.window.showInformationMessage(`✓ ${result.split('\n')[0]}`);
                } else {
                    vscode.window.showWarningMessage(`⚠ Chain issue detected — check output`);
                }
                refreshAll();
            } catch (e: any) {
                vscode.window.showErrorMessage(`SecChain Verify failed: ${e.message}`);
            }
        }),

        vscode.commands.registerCommand('secchain.show', async () => {
            const chain = loadChain();
            if (chain.length === 0) {
                vscode.window.showInformationMessage('SecChain: No blocks yet');
                return;
            }
            const lines = chain.map(b =>
                `#${b.n} | ${b.t.slice(0, 19)} | TMCP: ${b.tmcp} | ${b.h.slice(0, 20)}…`
            );
            showOutput('Blockchain', lines.join('\n'));
        }),

        vscode.commands.registerCommand('secchain.balance', async () => {
            const chain = loadChain();
            if (chain.length === 0) {
                vscode.window.showInformationMessage('SecChain: No chain');
                return;
            }
            const last = chain[chain.length - 1];
            vscode.window.showInformationMessage(
                `TrustyMCP Balance: ${last.tmcp} | Blocks: ${chain.length} | Since: ${chain[0].t.slice(0, 10)}`
            );
        }),

        vscode.commands.registerCommand('secchain.status', async () => {
            try {
                const result = await runSecChain('verify');
                showOutput('Security Status', result);
                refreshAll();
            } catch (e: any) {
                vscode.window.showErrorMessage(`SecChain Status failed: ${e.message}`);
            }
        })
    );

    // ── MCP Server Registration ──────────────────────────────────────
    // Register the SecChain MCP server so Copilot can use it
    try {
        const mcpServerPath = join(context.extensionPath, 'mcp-server.py');
        if (typeof vscode.lm?.registerMcpServerDefinitionProvider === 'function') {
            const provider: vscode.McpServerDefinitionProvider = {
                provideMcpServerDefinitions: async () => {
                    return [
                        new vscode.McpStdioServerDefinition({
                            label: 'SecChain',
                            command: 'python3',
                            args: [mcpServerPath],
                            version: '1.0.0',
                        })
                    ];
                }
            };
            context.subscriptions.push(
                vscode.lm.registerMcpServerDefinitionProvider('secchain', provider)
            );
            output.appendLine('SecChain MCP server registered for Copilot');
        } else {
            output.appendLine('MCP API not available — MCP server configured via mcp.json instead');
        }
    } catch {
        output.appendLine('MCP programmatic registration skipped — use mcp.json');
    }

    // Refresh every 5 minutes
    const timer = setInterval(refreshAll, 5 * 60 * 1000);
    context.subscriptions.push({ dispose: () => clearInterval(timer) });

    output.appendLine('SecChain extension activated');
}

export function deactivate() {}
