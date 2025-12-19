#!/usr/bin/env python3
"""
grenade/pki - enroll

One-time TLS bootstrap enrollment for a host:
- SSH to CA mint host to create a JWK provisioner token (step ca token)
- SSH to target host to run step certificate create with that token
- Writes:
  /etc/pki/hosts/host-key.pem
  /etc/pki/hosts/host-cert.pem
  /etc/pki/hosts/ca-chain-cert.pem
- Optionally enables renewal timers (best-effort)

Exit codes:
  0 = success
  2 = enrollment failed for at least one reason
  3 = runtime/config error
"""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


def run(cmd: List[str], *, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def shell_escape(s: str) -> str:
    return shlex.quote(s)


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


def normalize(s: str) -> str:
    return s.strip().lower()


class SSH:
    def __init__(
        self, user: str, port: int, timeout: int, proxy_jump: Optional[str]
    ) -> None:
        self.user = user
        self.port = port
        self.timeout = timeout
        self.proxy_jump = proxy_jump

    def base(self) -> List[str]:
        cmd = [
            "ssh",
            "-p",
            str(self.port),
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            f"ConnectTimeout={self.timeout}",
        ]
        if self.proxy_jump:
            cmd += ["-J", self.proxy_jump]
        return cmd

    def exec(
        self, host: str, cmd: str, *, sudo: bool = False, timeout: int = 120
    ) -> Tuple[int, str, str]:
        if sudo:
            remote = f"sudo -n bash -lc {shell_escape(cmd)}"
        else:
            remote = f"bash -lc {shell_escape(cmd)}"
        full = self.base() + [f"{self.user}@{host}", remote]
        cp = run(full, timeout=timeout)
        return cp.returncode, (cp.stdout or "").strip(), (cp.stderr or "").strip()


def find_site_and_host(
    cfg: Dict[str, Any], site_name: str, host_sel: str
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    sites = cfg.get("sites", [])
    if not isinstance(sites, list):
        raise RuntimeError("config.sites must be a list")

    site_name_n = normalize(site_name)
    host_sel_n = normalize(host_sel)

    site_obj: Optional[Dict[str, Any]] = None
    for s in sites:
        if isinstance(s, dict) and normalize(s.get("name", "")) == site_name_n:
            site_obj = s
            break
    if not site_obj:
        raise RuntimeError(f"Site not found: {site_name}")

    hosts = site_obj.get("hosts", []) or []
    if not isinstance(hosts, list):
        raise RuntimeError(f"sites[{site_name}].hosts must be a list")

    for h in hosts:
        if not isinstance(h, dict):
            continue
        hn = normalize(h.get("hostname", ""))
        fqdn = normalize(h.get("fqdn", ""))
        if host_sel_n in (hn, fqdn):
            return site_obj, h

    raise RuntimeError(f"Host not found in site {site_name}: {host_sel}")


def compute_fqdn(
    cfg: Dict[str, Any], site: Dict[str, Any], host: Dict[str, Any]
) -> str:
    fqdn = normalize(host.get("fqdn") or "")
    if fqdn:
        return fqdn
    hn = normalize(host["hostname"])
    suffix = normalize(site["name"]) + "." + normalize(cfg["global"]["internal_suffix"])
    return f"{hn}.{suffix}"


def read_local_root_pem(cfg: Dict[str, Any]) -> str:
    path = require(cfg, "global.ca.root_ca_pem")
    p = Path(path).expanduser()
    if not p.exists():
        raise RuntimeError(f"Missing local root CA PEM: {p}")
    s = p.read_text(encoding="utf-8")
    if "BEGIN CERTIFICATE" not in s:
        raise RuntimeError(f"Root CA PEM does not look like a certificate: {p}")
    return s


def mint_token_on_ca(ssh: SSH, cfg: Dict[str, Any], fqdn: str) -> str:
    ca_url = require(cfg, "global.ca.url")
    prov = require(cfg, "global.ca.provisioners.x509_hosts")
    ca_host = require(cfg, "global.ca.token_mint_host")
    ca_user = require(cfg, "global.ca.token_mint_user")
    ca_root = cfg_get(
        cfg, "global.ca.token_mint_root_crt", "/etc/step-ca/certs/root_ca.crt"
    )

    # Use a dedicated SSH session object for CA mint host if user differs
    ca_ssh = SSH(
        user=ca_user, port=ssh.port, timeout=ssh.timeout, proxy_jump=ssh.proxy_jump
    )

    cmd = f"""
set -euo pipefail
command -v step >/dev/null 2>&1
step ca token {shell_escape(fqdn)} \
  --provisioner {shell_escape(prov)} \
  --ca-url {shell_escape(ca_url)} \
  --root {shell_escape(ca_root)}
"""
    rc, out, err = ca_ssh.exec(ca_host, cmd, sudo=False, timeout=60)
    if rc != 0 or not out.strip():
        raise RuntimeError(f"Failed to mint token on {ca_host} (rc={rc}): {err or out}")
    # token is printed to stdout
    return out.strip()


def install_root_pem_on_target(ssh: SSH, target: str, root_pem: str) -> None:
    # Ensure /etc/pki/ca/root-ca-cert.pem exists (used by renewal scripts)
    import base64

    b64 = base64.b64encode(root_pem.encode("utf-8")).decode("ascii")
    cmd = f"""
set -euo pipefail
install -d -m 0755 /etc/pki/ca
tmp="$(mktemp)"
echo {shell_escape(b64)} | base64 -d > "$tmp"
install -m 0644 "$tmp" /etc/pki/ca/root-ca-cert.pem
rm -f "$tmp"
"""
    rc, out, err = ssh.exec(target, cmd, sudo=True, timeout=60)
    if rc != 0:
        raise RuntimeError(
            f"Failed installing root CA on target {target} (rc={rc}): {err or out}"
        )


def enroll_tls_on_target(
    ssh: SSH,
    cfg: Dict[str, Any],
    site: Dict[str, Any],
    host: Dict[str, Any],
    fqdn: str,
    token: str,
) -> None:
    ca_url = require(cfg, "global.ca.url")
    tls_dir = require(cfg, "global.tls.file_layout.dir")
    key_name = require(cfg, "global.tls.file_layout.host_key_pem")
    crt_name = require(cfg, "global.tls.file_layout.host_cert_pem")
    chain_name = require(cfg, "global.tls.file_layout.ca_chain_pem")

    key_path = f"{tls_dir}/{key_name}"
    crt_path = f"{tls_dir}/{crt_name}"
    chain_path = f"{tls_dir}/{chain_name}"

    hn = normalize(host["hostname"])
    ip = (host.get("ip") or "").strip()
    include_short = cfg_get(
        cfg, "global.tls.host_cert.san_include_short_hostname", True
    )
    include_ip = cfg_get(cfg, "global.tls.host_cert.san_include_ip_if_stable", True)

    sans = [fqdn]
    if include_short:
        sans.append(hn)
    if include_ip and ip:
        sans.append(ip)

    san_flags = " ".join(f"--san {shell_escape(x)}" for x in sans)

    cmd = f"""
set -euo pipefail
command -v step >/dev/null 2>&1 || (echo "missing step-cli" >&2; exit 10)

install -d -m 0700 {shell_escape(tls_dir)}

# If cert+key already exist, do not overwrite.
if [[ -f {shell_escape(crt_path)} && -f {shell_escape(key_path)} ]]; then
  echo "already-enrolled"
  exit 0
fi

step certificate create {shell_escape(fqdn)} \
  {shell_escape(crt_path)} \
  {shell_escape(key_path)} \
  --token {shell_escape(token)} \
  --ca-url {shell_escape(ca_url)} \
  --root /etc/pki/ca/root-ca-cert.pem \
  {san_flags}

chmod 0600 {shell_escape(key_path)}
chmod 0644 {shell_escape(crt_path)}

# Build a chain file. Prefer issuer if present, else root only.
if [[ -f /etc/pki/ca/issuer-ca-cert.pem ]]; then
  cat /etc/pki/ca/issuer-ca-cert.pem /etc/pki/ca/root-ca-cert.pem > {shell_escape(chain_path)}
else
  cp /etc/pki/ca/root-ca-cert.pem {shell_escape(chain_path)}
fi
chmod 0644 {shell_escape(chain_path)}

echo "enrolled"
"""
    rc, out, err = ssh.exec(fqdn, cmd, sudo=True, timeout=120)
    if rc == 10:
        raise RuntimeError(
            f"{fqdn}: step-cli missing. Run 'script/reconcile' first (or install step-cli) before enrollment."
        )
    if rc != 0:
        raise RuntimeError(f"{fqdn}: TLS enrollment failed (rc={rc}): {err or out}")


def enable_timers_best_effort(ssh: SSH, fqdn: str) -> None:
    cmd = """
set -euo pipefail
command -v systemctl >/dev/null 2>&1 || exit 0
systemctl daemon-reload || true
systemctl enable --now infra-host-cert-renew.timer || true
systemctl enable --now infra-ssh-hostcert-renew.timer || true
systemctl enable --now infra-ssh-hostkey-rotate.timer || true
"""
    ssh.exec(fqdn, cmd, sudo=True, timeout=60)


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="enroll",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="One-time TLS enrollment for a host (bootstrap for renewal).",
        epilog=textwrap.dedent("""\
        Examples:
          ./script/enroll --config config/my-bansko-infra.yml --site kosherinata --host db01
          ./script/enroll --config config/my-bansko-infra.yml --site hanzalova --host ca
        """),
    )
    ap.add_argument("--config", required=True)
    ap.add_argument("--site", required=True)
    ap.add_argument(
        "--host", required=True, help="Short hostname or FQDN within the site"
    )
    ap.add_argument(
        "--ssh-user",
        default=None,
        help="Override reconciliation.ssh.default_user for target host",
    )
    ap.add_argument("--ssh-port", type=int, default=None)
    ap.add_argument(
        "--proxy-jump", default=None, help="Override reconciliation.ssh.proxy_jump"
    )
    args = ap.parse_args()

    try:
        cfg = load_yaml(args.config)
        site, host = find_site_and_host(cfg, args.site, args.host)
        fqdn = compute_fqdn(cfg, site, host)
        root_pem = read_local_root_pem(cfg)

        ssh_user = args.ssh_user or cfg_get(
            cfg, "reconciliation.ssh.default_user", "ops"
        )
        ssh_port = int(args.ssh_port or cfg_get(cfg, "reconciliation.ssh.port", 22))
        ssh_timeout = int(cfg_get(cfg, "reconciliation.ssh.connect_timeout_seconds", 8))
        proxy_jump = (
            args.proxy_jump
            if args.proxy_jump is not None
            else cfg_get(cfg, "reconciliation.ssh.proxy_jump", None)
        )

        ssh = SSH(
            user=ssh_user, port=ssh_port, timeout=ssh_timeout, proxy_jump=proxy_jump
        )

        # 1) Mint token on CA host
        token = mint_token_on_ca(ssh, cfg, fqdn)

        # 2) Ensure root CA PEM exists on target (for step bootstrap)
        install_root_pem_on_target(ssh, fqdn, root_pem)

        # 3) Enroll TLS cert+key
        enroll_tls_on_target(ssh, cfg, site, host, fqdn, token)

        # 4) Enable timers (best effort; reconcile will do the full job)
        enable_timers_best_effort(ssh, fqdn)

        print(f"Enrolled TLS identity for {fqdn}")
        return 0

    except Exception as ex:
        eprint(f"ERROR: {ex}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
