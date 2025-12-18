#!/usr/bin/env python3
"""
grenade/pki - verify

Config-driven verification of PKI/SSH posture across hosts and routers.
Runs from workstation and connects to targets over SSH (hosts) and TLS (routers).

Exit codes:
  0 = all checks passed (or only warnings)
  2 = drift detected / failures found
  3 = runtime error (bad config, missing deps, etc.)
"""

from __future__ import annotations

import argparse
import dataclasses
import os
import re
import shlex
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# -------------------------
# Utilities
# -------------------------

def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)

def run(cmd: List[str], *, check: bool = False, capture: bool = True, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        check=check,
        capture_output=capture,
        text=True,
        timeout=timeout,
    )

def shell_escape(s: str) -> str:
    return shlex.quote(s)

def human_join(xs: List[str]) -> str:
    return ", ".join(xs)

def load_yaml(path: str) -> Dict[str, Any]:
    try:
        import yaml  # type: ignore
    except Exception as ex:
        raise RuntimeError(
            "PyYAML is required. Install with: python3 -m pip install pyyaml "
            "or your distro package (python3-pyyaml)."
        ) from ex

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise RuntimeError("Config root must be a mapping/dict")
    return data

def normalize_hostname(s: str) -> str:
    return s.strip().lower()

def is_truthy(x: Any) -> bool:
    return bool(x) is True


# -------------------------
# Reporting
# -------------------------

@dataclasses.dataclass
class Finding:
    target: str
    severity: str  # "PASS" | "WARN" | "FAIL"
    check: str
    details: str

class Reporter:
    def __init__(self) -> None:
        self.findings: List[Finding] = []

    def add(self, target: str, severity: str, check: str, details: str) -> None:
        self.findings.append(Finding(target, severity, check, details))

    def passed(self, target: str, check: str, details: str = "") -> None:
        self.add(target, "PASS", check, details)

    def warn(self, target: str, check: str, details: str) -> None:
        self.add(target, "WARN", check, details)

    def fail(self, target: str, check: str, details: str) -> None:
        self.add(target, "FAIL", check, details)

    def summarize(self) -> Tuple[int, int, int]:
        p = sum(1 for f in self.findings if f.severity == "PASS")
        w = sum(1 for f in self.findings if f.severity == "WARN")
        f = sum(1 for f in self.findings if f.severity == "FAIL")
        return p, w, f

    def print(self, *, verbose: bool = False) -> None:
        # Stable grouping: by target then severity
        by_target: Dict[str, List[Finding]] = {}
        for f in self.findings:
            by_target.setdefault(f.target, []).append(f)

        sev_order = {"FAIL": 0, "WARN": 1, "PASS": 2}
        for tgt in sorted(by_target.keys()):
            items = sorted(by_target[tgt], key=lambda x: (sev_order.get(x.severity, 9), x.check))
            print(f"\n== {tgt} ==")
            for it in items:
                if it.severity == "PASS" and not verbose:
                    continue
                prefix = {"PASS": "[OK]  ", "WARN": "[WARN]", "FAIL": "[FAIL]"}.get(it.severity, "[?]")
                line = f"{prefix} {it.check}"
                if it.details:
                    line += f": {it.details}"
                print(line)


# -------------------------
# Config access helpers
# -------------------------

def cfg_get(cfg: Dict[str, Any], path: str, default: Any = None) -> Any:
    cur: Any = cfg
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur

def require(cfg: Dict[str, Any], path: str) -> Any:
    v = cfg_get(cfg, path, None)
    if v is None:
        raise RuntimeError(f"Missing required config key: {path}")
    return v


# -------------------------
# SSH runner
# -------------------------

@dataclasses.dataclass
class SSH:
    user: str
    port: int
    timeout: int
    proxy_jump: Optional[str]

    def cmd_base(self) -> List[str]:
        cmd = [
            "ssh",
            "-p", str(self.port),
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"ConnectTimeout={self.timeout}",
        ]
        if self.proxy_jump:
            cmd += ["-J", self.proxy_jump]
        return cmd

    def run(self, host: str, remote_cmd: str, *, sudo: bool = False, timeout: int = 30) -> Tuple[int, str, str]:
        if sudo:
            # Non-interactive sudo; if it fails, we treat as warning/fail depending on check
            remote_cmd = f"sudo -n bash -lc {shell_escape(remote_cmd)}"
        else:
            remote_cmd = f"bash -lc {shell_escape(remote_cmd)}"

        full = self.cmd_base() + [f"{self.user}@{host}", remote_cmd]
        try:
            cp = run(full, check=False, capture=True, timeout=timeout)
            return cp.returncode, cp.stdout.strip(), cp.stderr.strip()
        except subprocess.TimeoutExpired:
            return 124, "", "timeout"


# -------------------------
# Checks
# -------------------------

def detect_os_family(ssh: SSH, target: str, rep: Reporter) -> Optional[Tuple[str, str]]:
    rc, out, err = ssh.run(target, "cat /etc/os-release 2>/dev/null || true")
    if rc != 0 or not out:
        rep.warn(target, "os-detect", f"Unable to read /etc/os-release (rc={rc}): {err or 'no output'}")
        return None

    id_like = ""
    os_id = ""
    for line in out.splitlines():
        if line.startswith("ID_LIKE="):
            id_like = line.split("=", 1)[1].strip().strip('"')
        if line.startswith("ID="):
            os_id = line.split("=", 1)[1].strip().strip('"')

    fam = "unknown"
    if "fedora" in (id_like + " " + os_id):
        fam = "fedora"
    elif "debian" in (id_like + " " + os_id) or os_id in ("ubuntu",):
        fam = "ubuntu"

    rep.passed(target, "os-detect", f"{os_id} (like: {id_like})")
    return fam, os_id

def check_file_perms(ssh: SSH, target: str, path: str, want_mode: str, want_owner: str, rep: Reporter, label: str) -> bool:
    rc, out, err = ssh.run(target, f"stat -c '%a %U:%G %n' {shell_escape(path)} 2>/dev/null")
    if rc != 0 or not out:
        rep.fail(target, label, f"Missing or unreadable: {path}")
        return False
    mode, owner, _ = out.split(" ", 2)
    ok = True
    if mode != want_mode:
        rep.fail(target, label, f"{path} mode {mode} != {want_mode}")
        ok = False
    if owner != want_owner:
        rep.fail(target, label, f"{path} owner {owner} != {want_owner}")
        ok = False
    if ok:
        rep.passed(target, label, f"{path} perms OK ({mode} {owner})")
    return ok

def check_tls_host_material(ssh: SSH, target: str, cfg: Dict[str, Any], fqdn: str, rep: Reporter) -> None:
    d = require(cfg, "global.tls.file_layout.dir")
    key = os.path.join(d, require(cfg, "global.tls.file_layout.host_key_pem"))
    crt = os.path.join(d, require(cfg, "global.tls.file_layout.host_cert_pem"))
    chain = os.path.join(d, require(cfg, "global.tls.file_layout.ca_chain_pem"))

    check_file_perms(ssh, target, key, "600", "root:root", rep, "tls-host-key")
    check_file_perms(ssh, target, crt, "644", "root:root", rep, "tls-host-cert")
    # chain: not strictly required on all setups, but expected in your design
    rc, out, err = ssh.run(target, f"test -f {shell_escape(chain)} && echo OK || true")
    if out.strip() == "OK":
        rep.passed(target, "tls-ca-chain", f"Present: {chain}")
    else:
        rep.warn(target, "tls-ca-chain", f"Missing: {chain} (some services may require chain)")

    # SAN contains fqdn
    rc, out, err = ssh.run(target, f"openssl x509 -in {shell_escape(crt)} -noout -text 2>/dev/null | sed -n '/Subject Alternative Name/,+2p'")
    if rc != 0 or not out:
        rep.fail(target, "tls-san", "Unable to parse cert SANs (openssl failed)")
    else:
        if fqdn in out:
            rep.passed(target, "tls-san", f"Includes {fqdn}")
        else:
            rep.fail(target, "tls-san", f"Missing expected SAN {fqdn}")

    # Expiry window (warn if < 14 days remaining, fail if already invalid)
    rc, _, _ = ssh.run(target, f"openssl x509 -in {shell_escape(crt)} -noout -checkend 0")
    if rc != 0:
        rep.fail(target, "tls-expiry", "Certificate appears expired or invalid now")
        return

    warn_days = 14
    warn_seconds = warn_days * 24 * 3600
    rc, _, _ = ssh.run(target, f"openssl x509 -in {shell_escape(crt)} -noout -checkend {warn_seconds}")
    if rc != 0:
        rep.warn(target, "tls-expiry", f"Certificate expires within {warn_days} days")
    else:
        rep.passed(target, "tls-expiry", f"Not expiring within {warn_days} days")

def check_systemd_timers(ssh: SSH, target: str, rep: Reporter) -> None:
    timers = [
        "infra-host-cert-renew.timer",
        "infra-ssh-hostcert-renew.timer",
        "infra-ssh-hostkey-rotate.timer",
    ]
    for t in timers:
        rc, out, err = ssh.run(target, f"systemctl is-enabled {shell_escape(t)} 2>/dev/null || true")
        if out.strip() == "enabled":
            rep.passed(target, "timer-enabled", t)
        elif out.strip() in ("disabled", "static", "masked"):
            rep.fail(target, "timer-enabled", f"{t}: {out.strip()}")
        else:
            rep.warn(target, "timer-enabled", f"{t}: unknown ({out.strip() or err or 'no output'})")

def check_sshd_config_contains(ssh: SSH, target: str, rep: Reporter) -> None:
    # Best-effort: greps sshd_config; use sudo since file may be root-owned.
    directives = {
        "TrustedUserCAKeys": "/etc/ssh/ssh_user_ca.pub",
        "HostCertificate": "/etc/ssh/ssh_host_ed25519_key-cert.pub",
    }
    for k, v in directives.items():
        rc, out, err = ssh.run(
            target,
            f"grep -E '^[[:space:]]*{re.escape(k)}[[:space:]]+{re.escape(v)}([[:space:]]|$)' /etc/ssh/sshd_config",
            sudo=True,
        )
        if rc == 0 and out:
            rep.passed(target, "sshd-config", f"{k} {v}")
        else:
            # Could be set via Include files; warn rather than fail.
            rep.warn(target, "sshd-config", f"Did not find '{k} {v}' in /etc/ssh/sshd_config (may be in included config)")

def check_ssh_reachability(ssh: SSH, target: str, rep: Reporter) -> bool:
    rc, out, err = ssh.run(target, "true", timeout=10)
    if rc == 0:
        rep.passed(target, "ssh", "reachable")
        return True
    rep.fail(target, "ssh", f"unreachable (rc={rc}): {err or out or 'no output'}")
    return False

def verify_host(ssh: SSH, cfg: Dict[str, Any], site: Dict[str, Any], host: Dict[str, Any], rep: Reporter) -> None:
    fqdn = normalize_hostname(host.get("fqdn") or "")
    if not fqdn:
        # Build from hostname + site suffix if not provided
        hn = normalize_hostname(host["hostname"])
        fqdn = f"{hn}.{site['name']}.{cfg['global']['internal_suffix']}"
    target = fqdn

    if not check_ssh_reachability(ssh, target, rep):
        return

    detect_os_family(ssh, target, rep)

    # TLS checks
    tls = host.get("tls", {})
    if is_truthy(tls.get("manage", True)):
        check_tls_host_material(ssh, target, cfg, fqdn, rep)
        check_systemd_timers(ssh, target, rep)
    else:
        rep.warn(target, "tls", "TLS management disabled for this host in config")

    # SSH checks
    ssh_cfg = host.get("ssh", {})
    if is_truthy(ssh_cfg.get("manage_host_cert", True)):
        check_sshd_config_contains(ssh, target, rep)
    else:
        rep.warn(target, "ssh-host-cert", "SSH host cert management disabled for this host in config")

    # iLO checks (inventory-level only here)
    ilo = host.get("ilo", {})
    if ilo and is_truthy(ilo.get("present", False)):
        strategy = ilo.get("strategy", "track")
        rep.passed(target, "ilo", f"present (strategy={strategy}, gen={ilo.get('generation','?')}, fqdn={ilo.get('fqdn','?')})")

def verify_router(router: Dict[str, Any], rep: Reporter) -> None:
    # Workstation-side TLS probe to router
    fqdn = normalize_hostname(router.get("mgmt_fqdn", ""))
    ip = router.get("mgmt_ip", "")
    name = router.get("name", fqdn or ip or "router")
    target = fqdn or ip or name

    # Basic TLS probe; OpenSSL s_client returns server chain; we check expiry and print subject/issuer.
    connect_host = ip or fqdn
    if not connect_host:
        rep.fail(target, "router", "Missing mgmt_ip/mgmt_fqdn")
        return

    cmd = [
        "openssl", "s_client",
        "-connect", f"{connect_host}:443",
        "-servername", fqdn or connect_host,
        "-showcerts",
    ]
    try:
        cp = run(cmd, check=False, capture=True, timeout=15)
    except Exception as ex:
        rep.fail(target, "router-tls", f"openssl probe failed: {ex}")
        return

    if cp.returncode != 0 and "BEGIN CERTIFICATE" not in (cp.stdout or ""):
        rep.fail(target, "router-tls", f"unreachable or TLS failure (rc={cp.returncode}): {cp.stderr.strip()}")
        return

    # Extract first cert and run openssl x509 checks locally
    m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", cp.stdout, re.S)
    if not m:
        rep.fail(target, "router-tls", "could not extract certificate")
        return
    cert_pem = m.group(0)

    # Subject/Issuer (info)
    cp2 = run(["openssl", "x509", "-noout", "-subject", "-issuer", "-enddate"], check=False, capture=True, timeout=10)
    # We need to feed cert via stdin:
    cp2 = subprocess.run(
        ["openssl", "x509", "-noout", "-subject", "-issuer", "-enddate"],
        input=cert_pem,
        text=True,
        capture_output=True,
        timeout=10,
    )
    info = " ".join(line.strip() for line in cp2.stdout.splitlines() if line.strip())
    rep.passed(target, "router-tls", info or "cert parsed")

    # Expiry check: warn if <30 days
    warn_days = 30
    warn_seconds = warn_days * 24 * 3600
    cp3 = subprocess.run(
        ["openssl", "x509", "-noout", "-checkend", str(warn_seconds)],
        input=cert_pem,
        text=True,
        capture_output=True,
        timeout=10,
    )
    if cp3.returncode != 0:
        rep.warn(target, "router-expiry", f"expires within {warn_days} days (or invalid)")
    else:
        rep.passed(target, "router-expiry", f"not expiring within {warn_days} days")


# -------------------------
# Main
# -------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        prog="verify",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Verify PKI/SSH posture across sites/hosts/routers.",
        epilog=textwrap.dedent("""\
        Examples:
          ./scripts/verify --config config/my-bansko-infra.yml
          ./scripts/verify --config config/my-bansko-infra.yml --site kosherinata
          ./scripts/verify --config config/my-bansko-infra.yml --site kosherinata --host db01
          ./scripts/verify --config config/my-bansko-infra.yml --routers-only
        """),
    )
    ap.add_argument("--config", required=True, help="Path to deployment config YAML")
    ap.add_argument("--site", help="Limit to a single site by name")
    ap.add_argument("--host", help="Limit to a single host by short hostname (within --site) or by FQDN")
    ap.add_argument("--routers-only", action="store_true", help="Verify routers only")
    ap.add_argument("--hosts-only", action="store_true", help="Verify hosts only")
    ap.add_argument("--verbose", action="store_true", help="Show PASS results")
    args = ap.parse_args()

    try:
        cfg = load_yaml(args.config)
    except Exception as ex:
        eprint(f"ERROR: {ex}")
        return 3

    rep = Reporter()

    # SSH defaults
    ssh_user = cfg_get(cfg, "reconciliation.ssh.default_user", "ops")
    ssh_port = int(cfg_get(cfg, "reconciliation.ssh.port", 22))
    ssh_timeout = int(cfg_get(cfg, "reconciliation.ssh.connect_timeout_seconds", 8))
    ssh_jump = cfg_get(cfg, "reconciliation.ssh.proxy_jump", None)

    ssh = SSH(user=ssh_user, port=ssh_port, timeout=ssh_timeout, proxy_jump=ssh_jump)

    sites = cfg.get("sites", [])
    if not isinstance(sites, list):
        eprint("ERROR: config.sites must be a list")
        return 3

    # Filters
    site_filter = normalize_hostname(args.site) if args.site else None
    host_filter = normalize_hostname(args.host) if args.host else None

    if args.routers_only and args.hosts_only:
        eprint("ERROR: --routers-only and --hosts-only are mutually exclusive")
        return 3

    verify_routers = not args.hosts_only
    verify_hosts = not args.routers_only

    for site in sites:
        if not isinstance(site, dict) or "name" not in site:
            rep.fail("config", "site-parse", f"Invalid site entry: {site!r}")
            continue

        site_name = normalize_hostname(site["name"])
        if site_filter and site_name != site_filter:
            continue

        # Routers
        if verify_routers:
            for router in site.get("routers", []) or []:
                if not isinstance(router, dict):
                    rep.fail(site_name, "router-parse", f"Invalid router entry: {router!r}")
                    continue
                verify_router(router, rep)

        # Hosts
        if verify_hosts:
            hosts = site.get("hosts", []) or []
            for host in hosts:
                if not isinstance(host, dict) or "hostname" not in host:
                    rep.fail(site_name, "host-parse", f"Invalid host entry: {host!r}")
                    continue
                hn = normalize_hostname(host.get("hostname", ""))
                fqdn = normalize_hostname(host.get("fqdn", ""))
                if host_filter:
                    # Allow filtering by short hostname OR fqdn
                    if host_filter not in (hn, fqdn):
                        continue
                # If user used --host without --site, require fqdn match to avoid ambiguity
                if args.host and not args.site and host_filter and host_filter == hn and fqdn and fqdn != host_filter:
                    # ambiguous short name without site: skip to avoid surprises
                    continue

                verify_host(ssh, cfg, site, host, rep)

    rep.print(verbose=args.verbose)
    p, w, f = rep.summarize()

    print(f"\nSummary: PASS={p} WARN={w} FAIL={f}")
    return 2 if f > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
