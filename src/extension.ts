import * as vscode from 'vscode';
import { execFile, exec } from 'child_process';
import { readFileSync, existsSync, appendFileSync, mkdirSync, writeFileSync } from 'fs';
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

const CHAIN_REL_PATH = 'secchain_data/chain.json';
const CLI_REL_PATH = 'secchain_cli.py';

function getWorkspaceRoot(): string {
    return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath || '';
}

function getChainPath(): string {
    return join(getWorkspaceRoot(), CHAIN_REL_PATH);
}

function getCliPath(): string {
    return join(getWorkspaceRoot(), CLI_REL_PATH);
}

// ── Helpers ──────────────────────────────────────────────────────────
function loadChain(): Block[] {
    try {
        const path = getChainPath();
        if (!path || !existsSync(path)) { return []; }
        return JSON.parse(readFileSync(path, 'utf-8'));
    } catch {
        return [];
    }
}

function runSecChain(cmd: string): Promise<string> {
    const cli = getCliPath();
    if (!cli) { return Promise.reject(new Error('No workspace open')); }
    
    return new Promise((resolve, reject) => {
        execFile('python3', [cli, cmd], { timeout: 30000, cwd: getWorkspaceRoot() }, (err, stdout, stderr) => {
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
            const fileKeys = Object.keys(b.s).filter(k => k.startsWith('file:'));
            const checkKeys = Object.keys(b.s).filter(k => !k.startsWith('file:'));
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

// ── Helper: run shell command ────────────────────────────────────────
function shellCmd(cmd: string): Promise<string> {
    return new Promise((resolve) => {
        exec(cmd, { timeout: 10000 }, (err, stdout) => {
            resolve(err ? '' : stdout.trim());
        });
    });
}

function shellCmdWithStatus(cmd: string): Promise<{ out: string; ok: boolean }> {
    return new Promise((resolve) => {
        exec(cmd, { timeout: 30000 }, (err, stdout, stderr) => {
            resolve({ out: (stdout || stderr || '').trim(), ok: !err });
        });
    });
}

// ── Persistent security log ──────────────────────────────────────────
function getLogPath(): string {
    const root = getWorkspaceRoot();
    const dir = join(root, 'secchain_data');
    if (!existsSync(dir)) { mkdirSync(dir, { recursive: true }); }
    return join(dir, 'security.log');
}

function logEntry(category: string, message: string) {
    const ts = new Date().toISOString();
    const line = `[${ts}] [${category}] ${message}\n`;
    try {
        appendFileSync(getLogPath(), line);
    } catch { /* ignore */ }
}

// ── Prevention fix definitions ───────────────────────────────────────
interface PreventionFix {
    name: string;
    check: string;
    isOk: (result: string) => boolean;
    fix: string;
    description: string;
}

const PREVENTION_FIXES: PreventionFix[] = [
    {
        name: 'ClamAV Antivirus',
        check: 'systemctl is-active clamav-daemon 2>/dev/null',
        isOk: (r) => r === 'active',
        fix: 'sudo systemctl start clamav-daemon && sudo systemctl enable clamav-daemon',
        description: 'Start and enable ClamAV antivirus daemon',
    },
    {
        name: 'Kernel dmesg_restrict',
        check: 'sysctl -n kernel.dmesg_restrict 2>/dev/null',
        isOk: (r) => r === '1',
        fix: 'sudo sysctl -w kernel.dmesg_restrict=1',
        description: 'Restrict kernel log access to root only',
    },
    {
        name: 'ICMP Ping Reply',
        check: 'sysctl -n net.ipv4.icmp_echo_ignore_all 2>/dev/null',
        isOk: (r) => r === '1',
        fix: 'sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1',
        description: 'Make machine invisible to ping scans',
    },
    {
        name: 'Auditd',
        check: 'systemctl is-active auditd 2>/dev/null',
        isOk: (r) => r === 'active',
        fix: 'sudo systemctl start auditd && sudo systemctl enable auditd',
        description: 'Start system audit logging',
    },
    {
        name: 'UFW Firewall',
        check: 'sudo ufw status 2>/dev/null | head -1',
        isOk: (r) => r.includes('active'),
        fix: 'sudo ufw --force enable',
        description: 'Enable firewall',
    },
    {
        name: 'Fail2Ban',
        check: 'systemctl is-active fail2ban 2>/dev/null',
        isOk: (r) => r === 'active',
        fix: 'sudo systemctl start fail2ban && sudo systemctl enable fail2ban',
        description: 'Start brute-force protection',
    },
    {
        name: 'SSH Server (should be off)',
        check: 'systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null',
        isOk: (r) => r !== 'active',
        fix: 'sudo systemctl stop sshd 2>/dev/null; sudo systemctl stop ssh 2>/dev/null; sudo systemctl disable sshd 2>/dev/null; sudo systemctl disable ssh 2>/dev/null',
        description: 'Stop and disable SSH server',
    },
    {
        name: 'Bluetooth (disconnect unknown)',
        check: 'bluetoothctl devices Connected 2>/dev/null | wc -l',
        isOk: (r) => (parseInt(r) || 0) === 0,
        fix: 'bluetoothctl disconnect 2>/dev/null; sudo systemctl stop bluetooth',
        description: 'Disconnect all BT devices and stop service',
    },
    {
        name: 'Remote Access Tools',
        check: 'pgrep -la "vnc|rdp|teamviewer|anydesk" 2>/dev/null | wc -l',
        isOk: (r) => (parseInt(r) || 0) === 0,
        fix: 'sudo pkill -f vnc 2>/dev/null; sudo pkill -f rdp 2>/dev/null; sudo pkill -f teamviewer 2>/dev/null; sudo pkill -f anydesk 2>/dev/null',
        description: 'Kill all remote access processes',
    },
];

// ── Protection check definitions ────────────────────────────────────
interface ProtectionCheck {
    name: string;
    icon: string;
    command: string;
    evaluate: (result: string) => { status: string; ok: boolean };
}

const PROTECTION_CHECKS: ProtectionCheck[] = [
    {
        name: 'UFW Firewall',
        icon: 'shield',
        command: 'sudo ufw status 2>/dev/null | head -1',
        evaluate: (r) => r.includes('active')
            ? { status: 'Active', ok: true }
            : { status: 'INACTIVE', ok: false },
    },
    {
        name: 'Fail2Ban',
        icon: 'lock',
        command: 'systemctl is-active fail2ban 2>/dev/null',
        evaluate: (r) => r === 'active'
            ? { status: 'Active', ok: true }
            : { status: 'INACTIVE', ok: false },
    },
    {
        name: 'ClamAV Antivirus',
        icon: 'bug',
        command: 'systemctl is-active clamav-daemon 2>/dev/null',
        evaluate: (r) => r === 'active'
            ? { status: 'Active', ok: true }
            : { status: 'INACTIVE', ok: false },
    },
    {
        name: 'AppArmor',
        icon: 'verified',
        command: 'cat /sys/module/apparmor/parameters/enabled 2>/dev/null',
        evaluate: (r) => r === 'Y'
            ? { status: 'Enabled', ok: true }
            : { status: 'DISABLED', ok: false },
    },
    {
        name: 'SSH Server',
        icon: 'terminal',
        command: 'systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null',
        evaluate: (r) => r === 'active'
            ? { status: 'RUNNING (risk)', ok: false }
            : { status: 'Off (safe)', ok: true },
    },
    {
        name: 'Open Ports',
        icon: 'globe',
        command: 'ss -tlnp 2>/dev/null | grep -c LISTEN || echo 0',
        evaluate: (r) => {
            const n = parseInt(r) || 0;
            return n === 0
                ? { status: 'None (secure)', ok: true }
                : { status: `${n} open`, ok: false };
        },
    },
    {
        name: 'Bluetooth',
        icon: 'radio-tower',
        command: 'systemctl is-active bluetooth 2>/dev/null',
        evaluate: (r) => r === 'active'
            ? { status: 'Active (monitor)', ok: true }
            : { status: 'Off', ok: true },
    },
    {
        name: 'BT Devices Connected',
        icon: 'plug',
        command: 'bluetoothctl devices Connected 2>/dev/null | wc -l',
        evaluate: (r) => {
            const n = parseInt(r) || 0;
            return n === 0
                ? { status: 'None', ok: true }
                : { status: `${n} connected`, ok: false };
        },
    },
    {
        name: 'Kernel ASLR',
        icon: 'symbol-key',
        command: 'sysctl -n kernel.randomize_va_space 2>/dev/null',
        evaluate: (r) => r === '2'
            ? { status: 'Full (2)', ok: true }
            : { status: `Weak (${r})`, ok: false },
    },
    {
        name: 'dmesg_restrict',
        icon: 'eye-closed',
        command: 'sysctl -n kernel.dmesg_restrict 2>/dev/null',
        evaluate: (r) => r === '1'
            ? { status: 'Restricted', ok: true }
            : { status: 'OPEN (fix)', ok: false },
    },
    {
        name: 'Auditd',
        icon: 'notebook',
        command: 'systemctl is-active auditd 2>/dev/null',
        evaluate: (r) => r === 'active'
            ? { status: 'Active', ok: true }
            : { status: 'INACTIVE', ok: false },
    },
    {
        name: 'chkrootkit',
        icon: 'search',
        command: 'which chkrootkit 2>/dev/null',
        evaluate: (r) => r
            ? { status: 'Installed', ok: true }
            : { status: 'NOT INSTALLED', ok: false },
    },
    {
        name: 'rkhunter',
        icon: 'search',
        command: 'which rkhunter 2>/dev/null',
        evaluate: (r) => r
            ? { status: 'Installed', ok: true }
            : { status: 'NOT INSTALLED', ok: false },
    },
    {
        name: 'Remote Access',
        icon: 'remote',
        command: 'pgrep -la "vnc|rdp|teamviewer|anydesk" 2>/dev/null | wc -l',
        evaluate: (r) => {
            const n = parseInt(r) || 0;
            return n === 0
                ? { status: 'None detected', ok: true }
                : { status: `${n} processes!`, ok: false };
        },
    },
];

// ── Cached protection results ────────────────────────────────────────
interface ProtectionResult {
    name: string;
    status: string;
    ok: boolean;
    icon: string;
}

let lastProtectionResults: ProtectionResult[] = [];
let lastScanTime = '';

async function runProtectionScan(): Promise<ProtectionResult[]> {
    const results: ProtectionResult[] = [];
    for (const check of PROTECTION_CHECKS) {
        const raw = await shellCmd(check.command);
        const { status, ok } = check.evaluate(raw);
        results.push({ name: check.name, status, ok, icon: check.icon });
    }
    lastProtectionResults = results;
    lastScanTime = new Date().toLocaleTimeString();
    return results;
}

// ── Tree view: Protection Status ─────────────────────────────────────
class ProtectionTreeProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
    private _onDidChange = new vscode.EventEmitter<void>();
    readonly onDidChangeTreeData = this._onDidChange.event;

    refresh() { this._onDidChange.fire(); }

    getTreeItem(el: vscode.TreeItem) { return el; }

    getChildren(): vscode.TreeItem[] {
        if (lastProtectionResults.length === 0) {
            const item = new vscode.TreeItem('Click "Scan Protection" to check');
            item.iconPath = new vscode.ThemeIcon('refresh');
            item.command = { command: 'secchain.protection', title: 'Scan' };
            return [item];
        }

        const items: vscode.TreeItem[] = [];

        // Summary header
        const passed = lastProtectionResults.filter(r => r.ok).length;
        const total = lastProtectionResults.length;
        const header = new vscode.TreeItem(`${passed}/${total} checks passed — ${lastScanTime}`);
        header.iconPath = new vscode.ThemeIcon(passed === total ? 'pass' : 'warning');
        items.push(header);

        // Individual checks
        for (const r of lastProtectionResults) {
            const item = new vscode.TreeItem(`${r.name}: ${r.status}`);
            item.iconPath = new vscode.ThemeIcon(r.ok ? 'pass' : 'error');
            item.tooltip = `${r.name} — ${r.status}`;
            items.push(item);
        }

        return items;
    }
}

// ── Protection Log (persistent) ──────────────────────────────────────
function getProtectionLogPath(): string {
    return join(getWorkspaceRoot(), 'secchain_data', 'protection.log');
}

function logProtection(entry: string) {
    const logPath = getProtectionLogPath();
    try {
        const dir = join(getWorkspaceRoot(), 'secchain_data');
        if (!existsSync(dir)) { mkdirSync(dir, { recursive: true }); }
        const timestamp = new Date().toISOString();
        appendFileSync(logPath, `[${timestamp}] ${entry}\n`);
    } catch { /* ignore */ }
}

function readProtectionLog(): string[] {
    try {
        const logPath = getProtectionLogPath();
        if (!existsSync(logPath)) { return []; }
        return readFileSync(logPath, 'utf-8').split('\n').filter(l => l.trim());
    } catch { return []; }
}

// ── Prevention definitions ───────────────────────────────────────────
interface PreventAction {
    name: string;
    check: string;
    fix: string;
    verify: string;
    description: string;
}

const PREVENT_ACTIONS: PreventAction[] = [
    {
        name: 'Enable ClamAV',
        check: 'systemctl is-active clamav-daemon 2>/dev/null',
        fix: 'sudo systemctl start clamav-daemon && sudo systemctl enable clamav-daemon',
        verify: 'systemctl is-active clamav-daemon 2>/dev/null',
        description: 'Start and enable antivirus daemon',
    },
    {
        name: 'Restrict dmesg',
        check: 'sysctl -n kernel.dmesg_restrict 2>/dev/null',
        fix: 'sudo sysctl -w kernel.dmesg_restrict=1',
        verify: 'sysctl -n kernel.dmesg_restrict 2>/dev/null',
        description: 'Block non-root users from reading kernel logs',
    },
    {
        name: 'Enable Auditd',
        check: 'systemctl is-active auditd 2>/dev/null',
        fix: 'sudo systemctl start auditd && sudo systemctl enable auditd',
        verify: 'systemctl is-active auditd 2>/dev/null',
        description: 'Start system audit logging',
    },
    {
        name: 'Stop SSH',
        check: 'systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null',
        fix: 'sudo systemctl stop sshd 2>/dev/null; sudo systemctl stop ssh 2>/dev/null; sudo systemctl disable sshd 2>/dev/null; sudo systemctl disable ssh 2>/dev/null',
        verify: 'systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null',
        description: 'Stop and disable SSH server',
    },
    {
        name: 'Block Ping',
        check: 'sysctl -n net.ipv4.icmp_echo_ignore_all 2>/dev/null',
        fix: 'sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1',
        verify: 'sysctl -n net.ipv4.icmp_echo_ignore_all 2>/dev/null',
        description: 'Make machine invisible to ping scans',
    },
    {
        name: 'Stop Bluetooth',
        check: 'systemctl is-active bluetooth 2>/dev/null',
        fix: 'sudo systemctl stop bluetooth',
        verify: 'systemctl is-active bluetooth 2>/dev/null',
        description: 'Stop Bluetooth service',
    },
    {
        name: 'Kill Remote Access',
        check: 'pgrep -la "vnc|rdp|teamviewer|anydesk" 2>/dev/null | wc -l',
        fix: 'sudo pkill -f vnc 2>/dev/null; sudo pkill -f rdp 2>/dev/null; sudo pkill -f teamviewer 2>/dev/null; sudo pkill -f anydesk 2>/dev/null',
        verify: 'pgrep -la "vnc|rdp|teamviewer|anydesk" 2>/dev/null | wc -l',
        description: 'Kill all remote access processes',
    },
];

function runShellFix(cmd: string): Promise<{ stdout: string; ok: boolean }> {
    return new Promise((resolve) => {
        exec(cmd, { timeout: 30000 }, (err, stdout, stderr) => {
            resolve({ stdout: (stdout || stderr || '').trim(), ok: !err });
        });
    });
}

// ── Tree view: Protection Log ────────────────────────────────────────
class LogTreeProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
    private _onDidChange = new vscode.EventEmitter<void>();
    readonly onDidChangeTreeData = this._onDidChange.event;

    refresh() { this._onDidChange.fire(); }

    getTreeItem(el: vscode.TreeItem) { return el; }

    getChildren(): vscode.TreeItem[] {
        const lines = readProtectionLog();
        if (lines.length === 0) {
            const item = new vscode.TreeItem('No protection events logged yet');
            item.iconPath = new vscode.ThemeIcon('notebook');
            return [item];
        }
        // Show last 30 entries, most recent first
        return lines.slice(-30).reverse().map(line => {
            const item = new vscode.TreeItem(line.length > 80 ? line.slice(0, 80) + '…' : line);
            item.tooltip = line;
            if (line.includes('FIX') || line.includes('PREVENT')) {
                item.iconPath = new vscode.ThemeIcon('wrench');
            } else if (line.includes('FAIL') || line.includes('ERROR')) {
                item.iconPath = new vscode.ThemeIcon('error');
            } else if (line.includes('PASS') || line.includes('OK')) {
                item.iconPath = new vscode.ThemeIcon('pass');
            } else {
                item.iconPath = new vscode.ThemeIcon('circle-outline');
            }
            return item;
        });
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
    const protectionTree = new ProtectionTreeProvider();
    const logTree = new LogTreeProvider();
    vscode.window.registerTreeDataProvider('secchain.chainView', chainTree);
    vscode.window.registerTreeDataProvider('secchain.statusView', statusTree);
    vscode.window.registerTreeDataProvider('secchain.protectionView', protectionTree);
    vscode.window.registerTreeDataProvider('secchain.logView', logTree);

    function refreshAll() {
        updateStatusBar();
        chainTree.refresh();
        statusTree.refresh();
        protectionTree.refresh();
        logTree.refresh();
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
        }),

        vscode.commands.registerCommand('secchain.protection', async () => {
            vscode.window.showInformationMessage('SecChain: Scanning system protection...');
            const results = await runProtectionScan();
            protectionTree.refresh();

            // Log to output
            const passed = results.filter(r => r.ok).length;
            const failed = results.filter(r => !r.ok);
            output.clear();
            output.appendLine(`═══ Protection Scan — ${lastScanTime} ═══`);
            output.appendLine(`Result: ${passed}/${results.length} checks passed\n`);
            for (const r of results) {
                const mark = r.ok ? '✓' : '✗';
                output.appendLine(`  ${mark} ${r.name}: ${r.status}`);
            }
            if (failed.length > 0) {
                output.appendLine('\n═══ Issues Found ═══');
                for (const r of failed) {
                    output.appendLine(`  ⚠ ${r.name}: ${r.status}`);
                }
            }
            output.show(true);

            if (failed.length === 0) {
                vscode.window.showInformationMessage(`SecChain: All ${results.length} protection checks passed!`);
            } else {
                vscode.window.showWarningMessage(`SecChain: ${failed.length} protection issue(s) found — check output log`);
            }

            // Log to persistent file
            logProtection(`SCAN: ${passed}/${results.length} passed`);
            for (const r of failed) {
                logProtection(`FAIL: ${r.name} — ${r.status}`);
            }
            logTree.refresh();
        }),

        // ── Prevent: Auto-fix security issues ────────────────────────
        vscode.commands.registerCommand('secchain.prevent', async () => {
            const picks = PREVENT_ACTIONS.map(a => ({
                label: a.name,
                description: a.description,
                picked: false,
            }));

            const selected = await vscode.window.showQuickPick(picks, {
                canPickMany: true,
                placeHolder: 'Select security fixes to apply',
                title: 'SecChain: Prevent — Auto-fix Security Issues',
            });

            if (!selected || selected.length === 0) { return; }

            output.clear();
            output.appendLine('═══ SecChain Prevention ═══\n');
            logProtection('PREVENT: Started prevention run');

            let fixed = 0;
            let failed2 = 0;

            for (const pick of selected) {
                const action = PREVENT_ACTIONS.find(a => a.name === pick.label)!;
                output.appendLine(`▶ ${action.name}: ${action.description}`);
                output.appendLine(`  Running: ${action.fix}`);

                const result = await runShellFix(action.fix);

                if (result.ok) {
                    const verify = await shellCmd(action.verify);
                    output.appendLine(`  Result: ${verify}`);
                    output.appendLine(`  ✓ FIXED\n`);
                    logProtection(`FIX OK: ${action.name} — ${verify}`);
                    fixed++;
                } else {
                    output.appendLine(`  ✗ FAILED: ${result.stdout}\n`);
                    logProtection(`FIX FAIL: ${action.name} — ${result.stdout}`);
                    failed2++;
                }
            }

            output.appendLine(`═══ Done: ${fixed} fixed, ${failed2} failed ═══`);
            output.show(true);
            logProtection(`PREVENT: Done — ${fixed} fixed, ${failed2} failed`);

            await runProtectionScan();
            refreshAll();

            if (failed2 === 0) {
                vscode.window.showInformationMessage(`SecChain: ${fixed} security fix(es) applied!`);
            } else {
                vscode.window.showWarningMessage(`SecChain: ${fixed} fixed, ${failed2} failed — check log`);
            }
        }),

        // ── Prevent All: Fix everything at once ──────────────────────
        vscode.commands.registerCommand('secchain.preventAll', async () => {
            const confirm = await vscode.window.showWarningMessage(
                'Apply ALL security fixes? This will modify system services.',
                { modal: true },
                'Yes, Fix Everything'
            );
            if (confirm !== 'Yes, Fix Everything') { return; }

            output.clear();
            output.appendLine('═══ SecChain: Fix Everything ═══\n');
            logProtection('PREVENT ALL: Applying all fixes');

            let fixed = 0;
            let failed2 = 0;

            for (const action of PREVENT_ACTIONS) {
                const current = await shellCmd(action.check);
                const needsFix = action.name === 'Restrict dmesg' ? current !== '1'
                    : action.name === 'Block Ping' ? current !== '1'
                    : action.name === 'Stop SSH' ? current === 'active'
                    : action.name === 'Stop Bluetooth' ? current === 'active'
                    : action.name === 'Kill Remote Access' ? (parseInt(current) || 0) > 0
                    : current !== 'active';

                if (!needsFix) {
                    output.appendLine(`  ✓ ${action.name}: Already OK`);
                    continue;
                }

                output.appendLine(`  ▶ Fixing: ${action.name}...`);
                const result = await runShellFix(action.fix);
                if (result.ok) {
                    output.appendLine(`    ✓ Fixed`);
                    logProtection(`FIX OK: ${action.name}`);
                    fixed++;
                } else {
                    output.appendLine(`    ✗ Failed: ${result.stdout}`);
                    logProtection(`FIX FAIL: ${action.name}`);
                    failed2++;
                }
            }

            output.appendLine(`\n═══ Result: ${fixed} fixed, ${failed2} failed ═══`);
            output.show(true);
            logProtection(`PREVENT ALL: ${fixed} fixed, ${failed2} failed`);

            await runProtectionScan();
            refreshAll();

            vscode.window.showInformationMessage(`SecChain: ${fixed} fixed, ${failed2} failed`);
        }),

        // ── View Protection Log ──────────────────────────────────────
        vscode.commands.registerCommand('secchain.viewLog', async () => {
            const logPath = getProtectionLogPath();
            if (existsSync(logPath)) {
                const doc = await vscode.workspace.openTextDocument(logPath);
                await vscode.window.showTextDocument(doc);
            } else {
                vscode.window.showInformationMessage('No protection log yet. Run a scan first.');
            }
        }),

        // ── Clear Log ────────────────────────────────────────────────
        vscode.commands.registerCommand('secchain.clearLog', async () => {
            const logPath = getProtectionLogPath();
            if (existsSync(logPath)) {
                writeFileSync(logPath, '');
                logTree.refresh();
                vscode.window.showInformationMessage('Protection log cleared.');
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
                        new vscode.McpStdioServerDefinition(
                            'SecChain',
                            'python3',
                            [mcpServerPath],
                            {},
                            '1.0.0'
                        )
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
