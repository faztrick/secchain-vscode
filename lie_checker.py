#!/usr/bin/env python3
"""SecChain Lie Checker — self-learning claim verifier with alerts & file tracking. Stdlib only."""
import hashlib, json, os, subprocess, sys, time, signal
from datetime import datetime
from pathlib import Path

D = Path(os.path.dirname(os.path.abspath(__file__))) / "secchain_data"
HIST, LEARN, ALERTS, FBASE, LOG = D/"lie_history.json", D/"learned.json", D/"alerts.json", D/"file_baseline.json", D/"interactions.log"
R,Y,G,C,M,B,X,DM = "\033[91m","\033[93m","\033[92m","\033[96m","\033[95m","\033[1m","\033[0m","\033[2m"

# ── Probes: what the system ACTUALLY is ──
PROBES = {
    "clamav":     ("systemctl is-active clamav-daemon",                    lambda r: r=="active",        "ClamAV running",        ["clamav","antivirus","virus"]),
    "ufw":        ("sudo ufw status|head -1",                              lambda r: "active" in r,      "Firewall active",       ["ufw","firewall","iptables"]),
    "ssh_off":    ("systemctl is-active sshd||systemctl is-active ssh",     lambda r: r!="active", "SSH disabled", ["ssh","sshd","openssh"]),
    "bt_on":      ("systemctl is-active bluetooth",                         lambda r: r=="active",        "Bluetooth active",      ["bluetooth","bt"]),
    "ports":      ("ss -tlnp|grep -c LISTEN||echo 0",                      lambda r: _int(r)>0,          "Ports open",            ["port","listening"]),
    "no_remote":  ("pgrep -la 'vnc|rdp|teamviewer|anydesk'|wc -l",         lambda r: _int(r)==0,   "No remote tools",       ["vnc","rdp","teamviewer","anydesk","remote"]),
    "dmesg":      ("sysctl -n kernel.dmesg_restrict",                       lambda r: r=="1",             "Kernel logs restricted", ["dmesg","kernel"]),
    "ping":       ("sysctl -n net.ipv4.icmp_echo_ignore_all",               lambda r: r=="1",             "Hidden from ping",      ["ping","icmp"]),
    "auditd":     ("systemctl is-active auditd",                            lambda r: r=="active",        "Audit logging on",      ["audit","auditd"]),
    "fail2ban":   ("systemctl is-active fail2ban",                           lambda r: r=="active",        "Fail2Ban active",       ["fail2ban","ban"]),
    "one_user":   ("who|wc -l",                                             lambda r: _int(r)<=1,         "Single user logged in", ["one user","only me"]),
    "no_zombie":  ("ps aux|awk '$8==\"Z\"'|wc -l",                          lambda r: _int(r)==0,         "No zombie processes",   ["zombie","defunct"]),
    "no_estab":   ("ss -tnp state established|tail -n+2|wc -l",             lambda r: _int(r)==0,       "No established connections", ["connection","established","remote conn"]),
    "outbound":   ("ss -tnp state established|tail -n+2",                   lambda r: len(r.strip())>0,   "Outbound connections exist", ["outbound","internet"]),
}

def _int(s):
    try: return int(s.strip().split("\n")[0])
    except: return 0

def sh(cmd):
    try: return subprocess.run(cmd,shell=True,capture_output=True,text=True,timeout=10).stdout.strip()
    except: return ""

def jload(p):
    try:
        if p.exists(): return json.loads(p.read_text())
    except: pass
    return [] if "hist" in str(p) or "alert" in str(p) else {}

def jsave(p, d):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(d, indent=2, default=str))

def log(action, detail):
    D.mkdir(parents=True, exist_ok=True)
    with open(LOG,"a") as f: f.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {action:10s} | {detail}\n")

# ── Alert engine ──
def alert(sev, title, detail=""):
    icons = {"CRITICAL":"🚨","HIGH":"⚠️","MEDIUM":"⚡","LOW":"ℹ️"}
    colors = {"CRITICAL":f"\033[41m{B}","HIGH":f"{R}{B}","MEDIUM":Y,"LOW":C}
    a = {"id":hashlib.md5(f"{time.time()}{title}".encode()).hexdigest()[:8], "sev":sev, "title":title, "detail":detail, "ts":datetime.now().isoformat(), "ack":False}
    al = jload(ALERTS); al.append(a); jsave(ALERTS, al[-500:])
    print(f"{colors.get(sev,DM)}{icons.get(sev,'·')} [{sev}] {title}{X}")
    if detail: print(f"  {DM}{detail}{X}")
    log("ALERT", f"[{sev}] {title}: {detail}")
    return a

# ── Core: compare prompt vs reality ──
def check(claim):
    cl = claim.lower()
    neg = any(w in cl for w in ["not","no ","isn't","disabled","off","stopped","none"])
    hits = []
    for pid,(cmd,truth,label,kws) in PROBES.items():
        score = sum(1 for k in kws if k in cl)
        if score: hits.append((pid,cmd,truth,label,score))
    learned = jload(LEARN)
    for pat,pid in (learned.items() if isinstance(learned,dict) else []):
        if pat in cl and pid in PROBES:
            cmd,truth,label,kws = PROBES[pid]
            hits.append((pid,cmd,truth,label,3))
    if not hits:
        return {"claim":claim,"verdict":"UNKNOWN","confidence":0,"comparison":[]}
    hits.sort(key=lambda x:x[4], reverse=True)
    comps = []
    for pid,cmd,truth,label,score in hits[:3]:
        raw = sh(cmd)
        actual = truth(raw)
        comps.append({"probe":pid,"label":label,"actual":actual,"raw":raw[:80],"score":score})
    best = comps[0]
    match = (not neg) == best["actual"]
    verdict = "TRUE" if match else "LIE"
    conf = min(95, 50 + best["score"]*15)
    result = {"claim":claim,"verdict":verdict,"confidence":conf,"comparison":comps,"ts":datetime.now().isoformat()}
    h = jload(HIST); h.append(result); jsave(HIST, h[-500:])
    if verdict == "LIE": alert("MEDIUM", f"Lie: \"{claim}\"", f"{conf}% confidence")
    return result

# ── File baseline & diff ──
WATCH = [Path(os.path.dirname(os.path.abspath(__file__))), Path.home()/".ssh", Path("/etc/passwd"), Path("/etc/hosts")]
SKIP = {".git","__pycache__","node_modules","secchain_data",".bak"}

def fhash(p):
    try: return hashlib.sha256(p.read_bytes()).hexdigest()
    except: return "?"

def snap():
    s = {}
    for p in WATCH:
        if p.is_file(): s[str(p)] = {"h":fhash(p),"m":oct(p.stat().st_mode)}
        elif p.is_dir():
            for c in sorted(p.rglob("*")):
                if c.is_file() and not any(sk in str(c) for sk in SKIP):
                    try: s[str(c)] = {"h":fhash(c),"m":oct(c.stat().st_mode)}
                    except: pass
    return s

def baseline():
    s = snap(); jsave(FBASE, {"ts":datetime.now().isoformat(),"files":s}); log("BASELINE",f"{len(s)} files"); return s

def diff():
    bl = jload(FBASE)
    if "files" not in bl: return None
    old, cur = bl["files"], snap()
    ch = {"added":[],"removed":[],"modified":[],"perms":[]}
    for p in set(list(old)+list(cur)):
        if p in cur and p not in old: ch["added"].append(p)
        elif p in old and p not in cur: ch["removed"].append(p)
        elif old[p]["h"] != cur[p]["h"]: ch["modified"].append(p)
        elif old[p]["m"] != cur[p]["m"]: ch["perms"].append(p)
    for f in ch["added"]: alert("MEDIUM","New file",f)
    for f in ch["removed"]: alert("HIGH","File removed",f)
    for f in ch["perms"]: alert("HIGH","Permissions changed",f)
    total = sum(len(v) for v in ch.values())
    log("DIFF",f"{total} changes"); return ch

# ── Watch mode ──
_run = True
def _stop(s,f): global _run; _run=False; print(f"\n{Y}Stopped.{X}")

def watch(interval=30):
    global _run; _run=True; signal.signal(signal.SIGINT,_stop)
    print(f"\n{B}{C}SecChain Watch — {interval}s interval — Ctrl+C to stop{X}\n")
    if "files" not in jload(FBASE): baseline()
    n=0
    while _run:
        n+=1; print(f"{DM}── cycle {n} {datetime.now():%H:%M:%S} ──{X}")
        ch = diff()
        if ch and sum(len(v) for v in ch.values())==0: print(f"  {G}✓ Clean{X}")
        for pid in ["clamav","ssh_off","no_remote","dmesg"]:
            if pid in PROBES:
                cmd,truth,label,_ = PROBES[pid]
                if not truth(sh(cmd)): alert("HIGH",f"FAIL: {label}")
        baseline()
        for _ in range(interval):
            if not _run: break
            time.sleep(1)

# ── CLI ──
def main():
    if len(sys.argv)<2:
        print(f"""{B}SecChain Lie Checker{X} — self-learning verifier

  {C}check "claim"{X}    Compare prompt vs system reality
  {C}scan{X}             Full truth scan
  {C}stats{X}            History stats
  {C}learn "p" id{X}     Teach pattern
  {Y}alerts{X}           Show alerts    {Y}alerts clear{X}
  {M}track{X}            File diff      {M}baseline{X}
  {G}watch [sec]{X}      Live monitor""")
        return

    cmd = sys.argv[1]

    if cmd=="check" and len(sys.argv)>=3:
        r = check(" ".join(sys.argv[2:]))
        v,c = r["verdict"],r["confidence"]
        vc = G if v=="TRUE" else R if v=="LIE" else Y
        icon = "✓" if v=="TRUE" else "✗" if v=="LIE" else "?"
        print(f"\n  {vc}{B}{icon} {v} ({c}%){X}")
        print(f"  {B}CLAIM:{X} \"{r['claim']}\"")
        print(f"  {B}vs REALITY:{X}")
        for p in r.get("comparison",[]):
            m = f"{G}✓{X}" if p["actual"] else f"{R}✗{X}"
            print(f"    {m} {p['label']}: {DM}{p['raw'][:50]}{X}")

    elif cmd=="scan":
        print(f"\n  {B}═══ SYSTEM TRUTH ═══{X}\n")
        seen=set()
        for pid,(c,truth,label,_) in PROBES.items():
            if c in seen: continue
            seen.add(c); raw=sh(c); ok=truth(raw)
            m = f"{G}✓{X}" if ok else f"{R}✗{X}"
            print(f"  {m} {label}: {DM}{raw[:50]}{X}")

    elif cmd=="stats":
        h=jload(HIST)
        if not h: print(f"  {DM}No checks yet.{X}"); return
        t,tr,li = len(h), sum(1 for x in h if x.get("verdict")=="TRUE"), sum(1 for x in h if x.get("verdict")=="LIE")
        print(f"\n  {B}Stats:{X} {t} checks | {G}{tr} true{X} | {R}{li} lies{X} | lie rate: {Y}{li/max(t,1)*100:.0f}%{X}")

    elif cmd=="learn" and len(sys.argv)>=4:
        p,pid = sys.argv[2],sys.argv[3]
        if pid in PROBES:
            l=jload(LEARN); l[p.lower()]=pid; jsave(LEARN,l)
            print(f"  {G}✓ Learned: \"{p}\" → {pid}{X}")
        else: print(f"  {R}✗ Unknown probe{X}")

    elif cmd=="alerts":
        if len(sys.argv)>=3 and sys.argv[2]=="clear":
            jsave(ALERTS,[]); print(f"  {G}✓ Cleared{X}")
        else:
            al=jload(ALERTS)
            if not al: print(f"  {DM}No alerts.{X}"); return
            for a in al[-20:]:
                print(f"  {Y}[{a.get('sev','')}]{X} {a.get('ts','')[:19]} {a['title']}")

    elif cmd=="track":
        if "files" not in jload(FBASE):
            baseline(); print(f"  {G}✓ Baseline built. Run again after changes.{X}"); return
        ch=diff()
        if not ch: print(f"  {Y}No baseline.{X}"); return
        total=sum(len(v) for v in ch.values())
        if total==0: print(f"  {G}✓ No changes.{X}"); return
        for f in ch["added"]:    print(f"  {G}+ {f}{X}")
        for f in ch["removed"]:  print(f"  {R}- {f}{X}")
        for f in ch["modified"]: print(f"  {Y}~ {f}{X}")
        for f in ch["perms"]:    print(f"  {M}! {f}{X}")

    elif cmd=="baseline": s=baseline(); print(f"  {G}✓ {len(s)} files baselined{X}")
    elif cmd=="watch": watch(int(sys.argv[2]) if len(sys.argv)>=3 else 30)
    else: print("Unknown command.")

if __name__=="__main__": main()
