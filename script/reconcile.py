#!/usr/bin/env python3
"""
grenade/pki - reconcile

Config-driven reconciliation of PKI/SSH posture across sites/hosts/routers.
Runs from workstation, connects to targets over SSH, and applies changes safely.

Exit codes:
  0 = reconcile completed (may include warnings)
  2 = failures found (some targets could not be reconciled)
  3 = runtime/config error
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


def run(
    cmd: List[str], *, check: bool = False, capture: bool = True, timeout: int = 30
) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        check=check,
        capture_output=capture,
        text=True,
        timeout=timeout,
    )


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


def normalize_hostname(s: str) -> str:
    return s.strip().lower()


def is_truthy(x: Any) -> bool:
    return bool(x) is True


def read_local_file(path: str) -> str:
    p = Path(path).expanduser()
    if not p.exists():
        raise RuntimeError(f"Missing required local file: {p}")
    return p.read_text(encoding="utf-8")


def ensure_pem_looks_valid(pem: str, label: str) -> None:
    if "BEGIN CERTIFICATE" not in pem:
        raise RuntimeError(f"{label} does not look like a PEM certificate")
    if "END CERTIFICATE" not in pem:
        raise RuntimeError(f"{label} does not look like a PEM certificate")


def ensure_ssh_pubkey_looks_valid(pub: str, label: str) -> None:
    # minimal check: starts with ssh-ed25519 / ecdsa / rsa
    if not re.match(
        r"^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256)\s+[A-Za-z0-9+/=]+(\s+.*)?$",
        pub.strip(),
    ):
        raise RuntimeError(f"{label} does not look like an SSH public key line")


# -------------------------
# Reporting
# -------------------------


@dataclasses.dataclass
class Finding:
    target: str
    severity: str  # "INFO" | "WARN" | "FAIL"
    action: str
    details: str


class Reporter:
    def __init__(self) -> None:
        self.items: List[Finding] = []

    def info(self, target: str, action: str, details: str) -> None:
        self.items.append(Finding(target, "INFO", action, details))

    def warn(self, target: str, action: str, details: str) -> None:
        self.items.append(Finding(target, "WARN", action, details))

    def fail(self, target: str, action: str, details: str) -> None:
        self.items.append(Finding(target, "FAIL", action, details))

    def summarize(self) -> Tuple[int, int, int]:
        i = sum(1 for x in self.items if x.severity == "INFO")
        w = sum(1 for x in self.items if x.severity == "WARN")
        f = sum(1 for x in self.items if x.severity == "FAIL")
        return i, w, f

    def print(self) -> None:
        by_target: Dict[str, List[Finding]] = {}
        for x in self.items:
            by_target.setdefault(x.target, []).append(x)

        sev_order = {"FAIL": 0, "WARN": 1, "INFO": 2}
        for tgt in sorted(by_target.keys()):
            print(f"\n== {tgt} ==")
            for it in sorted(
                by_target[tgt], key=lambda z: (sev_order.get(z.severity, 9), z.action)
            ):
                prefix = {"INFO": "[..] ", "WARN": "[!!] ", "FAIL": "[XX] "}.get(
                    it.severity, "[?] "
                )
                print(f"{prefix}{it.action}: {it.details}")


# -------------------------
# SSH runner
# -------------------------


@dataclasses.dataclass
class SSH:
    user: str
    port: int
    timeout: int
    proxy_jump: Optional[str]
    dry_run: bool

    def cmd_base(self) -> List[str]:
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

    def run(
        self, host: str, remote_cmd: str, *, sudo: bool = False, timeout: int = 60
    ) -> Tuple[int, str, str]:
        if sudo:
            remote_cmd = f"sudo -n bash -lc {shell_escape(remote_cmd)}"
        else:
            remote_cmd = f"bash -lc {shell_escape(remote_cmd)}"

        full = self.cmd_base() + [f"{self.user}@{host}", remote_cmd]
        if self.dry_run:
            return 0, "", ""

        try:
            cp = run(full, check=False, capture=True, timeout=timeout)
            return cp.returncode, cp.stdout.strip(), cp.stderr.strip()
        except subprocess.TimeoutExpired:
            return 124, "", "timeout"


# -------------------------
# Remote installers (idempotent)
# -------------------------


def remote_write_file(
    ssh: SSH, target: str, dest: str, content: str, mode: str, rep: Reporter
) -> bool:
    # Use a temp file then install atomically.
    # Avoid here-doc quoting issues by base64 encoding.
    import base64

    b64 = base64.b64encode(content.encode("utf-8")).decode("ascii")
    cmd = f"""
set -euo pipefail
tmp="$(mktemp)"
echo {shell_escape(b64)} | base64 -d > "$tmp"
install -m {shell_escape(mode)} "$tmp" {shell_escape(dest)}
rm -f "$tmp"
"""
    rc, out, err = ssh.run(target, cmd, sudo=True, timeout=60)
    if rc == 0:
        rep.info(target, "write", f"{dest} (mode {mode})")
        return True
    rep.fail(target, "write", f"{dest}: rc={rc} {err or out or ''}".strip())
    return False


def remote_mkdir(ssh: SSH, target: str, path: str, mode: str, rep: Reporter) -> bool:
    cmd = f"install -d -m {shell_escape(mode)} {shell_escape(path)}"
    rc, out, err = ssh.run(target, cmd, sudo=True, timeout=30)
    if rc == 0:
        rep.info(target, "mkdir", f"{path} (mode {mode})")
        return True
    rep.fail(target, "mkdir", f"{path}: rc={rc} {err or out or ''}".strip())
    return False


def remote_systemctl(
    ssh: SSH, target: str, args: str, rep: Reporter, action: str
) -> bool:
    rc, out, err = ssh.run(target, f"systemctl {args}", sudo=True, timeout=60)
    if rc == 0:
        rep.info(target, action, f"systemctl {args}")
        return True
    rep.fail(target, action, f"systemctl {args}: rc={rc} {err or out or ''}".strip())
    return False


def remote_has_systemd(ssh: SSH, target: str) -> bool:
    rc, out, err = ssh.run(
        target,
        "command -v systemctl >/dev/null 2>&1 && echo yes || echo no",
        sudo=False,
        timeout=10,
    )
    return out.strip() == "yes"


def remote_os_family(ssh: SSH, target: str, rep: Reporter) -> Optional[str]:
    rc, out, err = ssh.run(
        target, "cat /etc/os-release 2>/dev/null || true", sudo=False, timeout=10
    )
    if rc != 0 or not out:
        rep.warn(target, "os", f"unable to read /etc/os-release: {err or 'no output'}")
        return None
    os_id = ""
    id_like = ""
    for line in out.splitlines():
        if line.startswith("ID="):
            os_id = line.split("=", 1)[1].strip().strip('"')
        if line.startswith("ID_LIKE="):
            id_like = line.split("=", 1)[1].strip().strip('"')
    blob = (os_id + " " + id_like).lower()
    if "fedora" in blob:
        rep.info(target, "os", f"{os_id} (like: {id_like})")
        return "fedora"
    if "ubuntu" in blob or "debian" in blob:
        rep.info(target, "os", f"{os_id} (like: {id_like})")
        return "ubuntu"
    rep.warn(target, "os", f"unknown: {os_id} (like: {id_like})")
    return "unknown"


# -------------------------
# Payloads (scripts + systemd units)
# -------------------------


def payload_infra_host_renew(ca_url: str, root_pem: str) -> str:
    # Renew existing host cert/key only. If missing, script exits 0 (reconcile warns elsewhere).
    return f"""#!/usr/bin/env bash
set -euo pipefail

CA_URL={shlex.quote(ca_url)}
ROOT_PEM={shlex.quote(root_pem)}

CERT=/etc/pki/hosts/host-cert.pem
KEY=/etc/pki/hosts/host-key.pem
TMP="${{CERT}}.new"

[[ -f "$CERT" && -f "$KEY" && -f "$ROOT_PEM" ]] || exit 0

step ca renew "$CERT" "$KEY" --ca-url "$CA_URL" --root "$ROOT_PEM" --out "$TMP" --force

if ! cmp -s "$CERT" "$TMP"; then
  install -m 0644 "$TMP" "$CERT"
  # Optional reload list
  if [[ -f /etc/infra/host-cert-reload.units ]]; then
    while IFS= read -r unit; do
      [[ -z "$unit" || "$unit" =~ ^# ]] && continue
      systemctl try-reload-or-restart "$unit" || true
    done < /etc/infra/host-cert-reload.units
  fi
fi

rm -f "$TMP"
"""


def payload_infra_ssh_hostcert_renew(ca_url: str, root_pem: str) -> str:
    # Creates host key if missing; attempts to issue host cert if step ssh is configured.
    return f"""#!/usr/bin/env bash
set -euo pipefail

CA_URL={shlex.quote(ca_url)}
ROOT_PEM={shlex.quote(root_pem)}

KEY=/etc/ssh/ssh_host_ed25519_key
PUB=/etc/ssh/ssh_host_ed25519_key.pub
CERT=/etc/ssh/ssh_host_ed25519_key-cert.pub

FQDN="$(hostname -f 2>/dev/null || hostname)"
SHORT="$(hostname -s 2>/dev/null || hostname)"

if [[ ! -f "$KEY" ]]; then
  ssh-keygen -t ed25519 -N '' -f "$KEY"
  chmod 600 "$KEY"
  chmod 644 "$PUB"
fi

# Only attempt if step is present
command -v step >/dev/null 2>&1 || exit 0

# Sign host key. This requires your step-ca SSH CA to be enabled and reachable.
# If step lacks auth/provisioning, this will fail; timer will keep trying.
step ssh certificate --host \\
  --principal "$FQDN" \\
  --principal "$SHORT" \\
  --ca-url "$CA_URL" \\
  --root "$ROOT_PEM" \\
  --force \\
  "$FQDN" \\
  "$PUB"

chmod 644 "$CERT" || true
systemctl try-reload-or-restart sshd || true
"""


def payload_infra_ssh_hostkey_rotate() -> str:
    return """#!/usr/bin/env bash
set -euo pipefail

MAX_AGE_DAYS="${MAX_AGE_DAYS:-60}"

KEY="/etc/ssh/ssh_host_ed25519_key"
PUB="/etc/ssh/ssh_host_ed25519_key.pub"

[[ -f "$KEY" ]] || exit 0

age_days=$(( ( $(date +%s) - $(stat -c %Y "$KEY") ) / 86400 ))
(( age_days >= MAX_AGE_DAYS )) || exit 0

tmp="${KEY}.new"
ssh-keygen -t ed25519 -N '' -f "$tmp"

install -m 600 "$tmp" "$KEY"
install -m 644 "${tmp}.pub" "$PUB"
rm -f "$tmp" "${tmp}.pub"

# Re-issue host cert after rotation
/usr/local/sbin/infra-ssh-hostcert-renew || true
"""


def unit_service(name: str, execstart: str, description: str) -> str:
    return f"""[Unit]
Description={description}
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart={execstart}
"""


def unit_timer_daily(name: str, description: str, randomized: str = "1h") -> str:
    return f"""[Unit]
Description={description}

[Timer]
OnCalendar=daily
RandomizedDelaySec={randomized}
Persistent=true

[Install]
WantedBy=timers.target
"""


def unit_timer_every_6h(description: str) -> str:
    return f"""[Unit]
Description={description}

[Timer]
OnCalendar=*-*-* 00,06,12,18:00:00
RandomizedDelaySec=20m
Persistent=true

[Install]
WantedBy=timers.target
"""


def unit_timer_weekly(description: str) -> str:
    return f"""[Unit]
Description={description}

[Timer]
OnCalendar=weekly
RandomizedDelaySec=2h
Persistent=true

[Install]
WantedBy=timers.target
"""


# -------------------------
# Reconcile operations
# -------------------------


def reconcile_trust(
    ssh: SSH,
    target: str,
    osfam: str,
    cfg: Dict[str, Any],
    root_pem_content: str,
    rep: Reporter,
) -> None:
    # Place root CA into OS trust anchors and run update command.
    if osfam == "fedora":
        anchor_dir = require(cfg, "global.tls.os_trust.fedora_anchor_dir")
        dest = f"{anchor_dir}/grenade-pki-root-ca.pem"
        remote_mkdir(ssh, target, anchor_dir, "755", rep)
        remote_write_file(ssh, target, dest, root_pem_content, "644", rep)
        remote_systemctl(ssh, target, "daemon-reload", rep, "systemd")
        # update-ca-trust
        rc, out, err = ssh.run(target, "update-ca-trust", sudo=True, timeout=60)
        if rc == 0:
            rep.info(target, "trust", "update-ca-trust")
        else:
            rep.fail(
                target, "trust", f"update-ca-trust failed: rc={rc} {err or out}".strip()
            )
    elif osfam == "ubuntu":
        anchor_dir = require(cfg, "global.tls.os_trust.ubuntu_anchor_dir")
        # Ubuntu expects *.crt in that directory; keep your *.pem rule elsewhere, but comply here.
        dest = f"{anchor_dir}/grenade-pki-root-ca.crt"
        remote_mkdir(ssh, target, anchor_dir, "755", rep)
        remote_write_file(ssh, target, dest, root_pem_content, "644", rep)
        rc, out, err = ssh.run(target, "update-ca-certificates", sudo=True, timeout=120)
        if rc == 0:
            rep.info(target, "trust", "update-ca-certificates")
        else:
            rep.fail(
                target,
                "trust",
                f"update-ca-certificates failed: rc={rc} {err or out}".strip(),
            )
    else:
        rep.warn(
            target,
            "trust",
            f"OS family {osfam} not supported for OS trust installation (yet)",
        )


def reconcile_tls_layout(
    ssh: SSH, target: str, cfg: Dict[str, Any], rep: Reporter
) -> None:
    d = require(cfg, "global.tls.file_layout.dir")
    remote_mkdir(ssh, target, d, "700", rep)
    # do not create keys/certs here: enrollment is separate
    rep.info(
        target, "tls-layout", f"ensured {d} exists (enrollment handled separately)"
    )


def reconcile_ssh_server_config(
    ssh: SSH, target: str, cfg: Dict[str, Any], ssh_user_ca_pub: str, rep: Reporter
) -> None:
    # Copy User CA to /etc/ssh/ssh_user_ca.pub
    dest_ca = require(cfg, "global.ssh.server_paths.trusted_user_ca_pub")
    remote_write_file(
        ssh,
        target,
        dest_ca,
        ssh_user_ca_pub + ("\n" if not ssh_user_ca_pub.endswith("\n") else ""),
        "644",
        rep,
    )

    # Ensure sshd_config.d drop-in (modern Fedora/Ubuntu)
    dropin_dir = "/etc/ssh/sshd_config.d"
    remote_mkdir(ssh, target, dropin_dir, "755", rep)

    host_cert = require(cfg, "global.ssh.server_paths.host_cert_pub")
    content = f"""# Managed by grenade/pki (do not edit here; edit repo + reconcile)
TrustedUserCAKeys {dest_ca}
HostCertificate {host_cert}
"""
    remote_write_file(
        ssh, target, f"{dropin_dir}/99-grenade-pki.conf", content, "644", rep
    )

    # Reload sshd
    ssh.run(target, "sshd -t", sudo=True, timeout=30)  # syntax check best-effort
    remote_systemctl(ssh, target, "try-reload-or-restart sshd", rep, "sshd")


def reconcile_systemd_payloads(
    ssh: SSH, target: str, cfg: Dict[str, Any], rep: Reporter
) -> None:
    if not remote_has_systemd(ssh, target):
        rep.warn(target, "systemd", "systemctl not present; skipping timers/units")
        return

    ca_url = require(cfg, "global.ca.url")
    root_pem_remote = "/etc/pki/ca/root-ca-cert.pem"  # remote standard; your verify script expects this too
    # Ensure /etc/pki/ca exists and install root there for step scripts
    remote_mkdir(ssh, target, "/etc/pki/ca", "755", rep)

    # Also write root pem to /etc/pki/ca/root-ca-cert.pem for step scripts
    root_pem_content = read_local_file(require(cfg, "global.ca.root_ca_pem"))
    ensure_pem_looks_valid(root_pem_content, "global.ca.root_ca_pem")
    remote_write_file(ssh, target, root_pem_remote, root_pem_content, "644", rep)

    # /etc/infra reload list directory (optional)
    remote_mkdir(ssh, target, "/etc/infra", "755", rep)

    # Scripts
    remote_write_file(
        ssh,
        target,
        "/usr/local/sbin/infra-host-renew",
        payload_infra_host_renew(ca_url, root_pem_remote),
        "755",
        rep,
    )
    remote_write_file(
        ssh,
        target,
        "/usr/local/sbin/infra-ssh-hostcert-renew",
        payload_infra_ssh_hostcert_renew(ca_url, root_pem_remote),
        "755",
        rep,
    )
    remote_write_file(
        ssh,
        target,
        "/usr/local/sbin/infra-ssh-hostkey-rotate",
        payload_infra_ssh_hostkey_rotate(),
        "755",
        rep,
    )

    # Units
    remote_write_file(
        ssh,
        target,
        "/etc/systemd/system/infra-host-cert-renew.service",
        unit_service(
            "infra-host-cert-renew.service",
            "/usr/local/sbin/infra-host-renew",
            "Renew host identity TLS certificate",
        ),
        "644",
        rep,
    )
    remote_write_file(
        ssh,
        target,
        "/etc/systemd/system/infra-host-cert-renew.timer",
        unit_timer_daily(
            "infra-host-cert-renew.timer", "Daily host TLS cert renewal check"
        ),
        "644",
        rep,
    )

    remote_write_file(
        ssh,
        target,
        "/etc/systemd/system/infra-ssh-hostcert-renew.service",
        unit_service(
            "infra-ssh-hostcert-renew.service",
            "/usr/local/sbin/infra-ssh-hostcert-renew",
            "Renew SSH host certificate",
        ),
        "644",
        rep,
    )
    remote_write_file(
        ssh,
        target,
        "/etc/systemd/system/infra-ssh-hostcert-renew.timer",
        unit_timer_every_6h("Renew SSH host certificate every 6 hours"),
        "644",
        rep,
    )

    remote_write_file(
        ssh,
        target,
        "/etc/systemd/system/infra-ssh-hostkey-rotate.service",
        unit_service(
            "infra-ssh-hostkey-rotate.service",
            "/usr/local/sbin/infra-ssh-hostkey-rotate",
            "Rotate SSH host key if aged",
        ),
        "644",
        rep,
    )
    remote_write_file(
        ssh,
        target,
        "/etc/systemd/system/infra-ssh-hostkey-rotate.timer",
        unit_timer_weekly("Weekly check for SSH host key rotation"),
        "644",
        rep,
    )

    # Enable timers
    remote_systemctl(ssh, target, "daemon-reload", rep, "systemd")
    remote_systemctl(
        ssh, target, "enable --now infra-host-cert-renew.timer", rep, "timer"
    )
    remote_systemctl(
        ssh, target, "enable --now infra-ssh-hostcert-renew.timer", rep, "timer"
    )
    remote_systemctl(
        ssh, target, "enable --now infra-ssh-hostkey-rotate.timer", rep, "timer"
    )


def reconcile_host(
    ssh: SSH,
    cfg: Dict[str, Any],
    site: Dict[str, Any],
    host: Dict[str, Any],
    rep: Reporter,
    root_pem_content: str,
    ssh_user_ca_pub: str,
) -> None:
    fqdn = normalize_hostname(host.get("fqdn") or "")
    if not fqdn:
        hn = normalize_hostname(host["hostname"])
        fqdn = f"{hn}.{site['name']}.{cfg['global']['internal_suffix']}"
    target = fqdn

    # Reachability
    rc, out, err = ssh.run(target, "true", sudo=False, timeout=10)
    if rc != 0:
        rep.fail(target, "ssh", f"unreachable: rc={rc} {err or out}".strip())
        return
    rep.info(target, "ssh", "reachable")

    osfam = remote_os_family(ssh, target, rep)
    if osfam is None:
        rep.fail(target, "os", "unable to detect OS")
        return

    # Trust + layout
    reconcile_trust(ssh, target, osfam, cfg, root_pem_content, rep)
    reconcile_tls_layout(ssh, target, cfg, rep)

    # SSH server config + CA pub
    reconcile_ssh_server_config(ssh, target, cfg, ssh_user_ca_pub, rep)

    # systemd scripts/units/timers
    reconcile_systemd_payloads(ssh, target, cfg, rep)

    # Enrollment gap warnings (actionable)
    tls_dir = require(cfg, "global.tls.file_layout.dir")
    host_cert = os.path.join(
        tls_dir, require(cfg, "global.tls.file_layout.host_cert_pem")
    )
    host_key = os.path.join(
        tls_dir, require(cfg, "global.tls.file_layout.host_key_pem")
    )

    rc, out, _ = ssh.run(
        target,
        f"test -f {shell_escape(host_cert)} -a -f {shell_escape(host_key)} && echo yes || echo no",
        sudo=True,
        timeout=10,
    )
    if out.strip() != "yes":
        rep.warn(
            target,
            "tls-enrollment",
            f"missing {host_cert} and/or {host_key}. Initial enrollment requires a one-time token (or pre-seeded material).",
        )

    # SSH host cert presence (cert issuance may require CA-side SSH enabled + auth)
    ssh_host_cert = require(cfg, "global.ssh.server_paths.host_cert_pub")
    rc, out, _ = ssh.run(
        target,
        f"test -f {shell_escape(ssh_host_cert)} && echo yes || echo no",
        sudo=True,
        timeout=10,
    )
    if out.strip() != "yes":
        rep.warn(
            target,
            "ssh-hostcert",
            f"missing {ssh_host_cert}. Timer will attempt issuance if step/SSH-CA is configured.",
        )


# -------------------------
# Routers (placeholder in this iteration)
# -------------------------


def reconcile_router(router: Dict[str, Any], rep: Reporter) -> None:
    # In this initial version we only record intent.
    # OPNsense UI certificate sync will be added as a dedicated module once you decide preferred mechanism
    # (CSR export/import vs API/backup patching vs HAProxy fronting).
    name = normalize_hostname(router.get("name", "router"))
    rep.warn(
        name,
        "router",
        "router reconciliation not implemented yet (tracking via verify for now)",
    )


# -------------------------
# Main
# -------------------------


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="reconcile",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Reconcile PKI/SSH posture across sites/hosts/routers.",
        epilog=textwrap.dedent("""\
        Examples:
          ./scripts/reconcile --config config/my-bansko-infra.yml
          ./scripts/reconcile --config config/my-bansko-infra.yml --site kosherinata
          ./scripts/reconcile --config config/my-bansko-infra.yml --site kosherinata --host db01
          ./scripts/reconcile --config config/my-bansko-infra.yml --dry-run
          ./scripts/reconcile --config config/my-bansko-infra.yml --routers-only
        """),
    )
    ap.add_argument("--config", required=True, help="Path to deployment config YAML")
    ap.add_argument("--site", help="Limit to a single site by name")
    ap.add_argument(
        "--host",
        help="Limit to a single host by short hostname (within --site) or by FQDN",
    )
    ap.add_argument(
        "--routers-only", action="store_true", help="Reconcile routers only"
    )
    ap.add_argument("--hosts-only", action="store_true", help="Reconcile hosts only")
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not change anything; print intended actions",
    )
    ap.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Limit number of targets processed (0 = no limit)",
    )
    ap.add_argument("--fail-fast", action="store_true", help="Stop on first failure")
    args = ap.parse_args()

    try:
        cfg = load_yaml(args.config)
    except Exception as ex:
        eprint(f"ERROR: {ex}")
        return 3

    # Load local artifacts
    root_ca_path = require(cfg, "global.ca.root_ca_pem")
    root_pem = read_local_file(root_ca_path)
    ensure_pem_looks_valid(root_pem, f"global.ca.root_ca_pem ({root_ca_path})")

    # SSH User CA public key must be versioned in repo as an artifact
    ssh_user_ca_path = "asset/ssh/ssh_user_ca.pub"
    ssh_user_ca_pub = read_local_file(ssh_user_ca_path)
    ensure_ssh_pubkey_looks_valid(ssh_user_ca_pub, f"{ssh_user_ca_path}")

    rep = Reporter()

    # SSH defaults
    ssh_user = cfg_get(cfg, "reconciliation.ssh.default_user", "ops")
    ssh_port = int(cfg_get(cfg, "reconciliation.ssh.port", 22))
    ssh_timeout = int(cfg_get(cfg, "reconciliation.ssh.connect_timeout_seconds", 8))
    ssh_jump = cfg_get(cfg, "reconciliation.ssh.proxy_jump", None)

    ssh = SSH(
        user=ssh_user,
        port=ssh_port,
        timeout=ssh_timeout,
        proxy_jump=ssh_jump,
        dry_run=args.dry_run,
    )

    sites = cfg.get("sites", [])
    if not isinstance(sites, list):
        eprint("ERROR: config.sites must be a list")
        return 3

    site_filter = normalize_hostname(args.site) if args.site else None
    host_filter = normalize_hostname(args.host) if args.host else None

    if args.routers_only and args.hosts_only:
        eprint("ERROR: --routers-only and --hosts-only are mutually exclusive")
        return 3

    do_routers = not args.hosts_only
    do_hosts = not args.routers_only

    processed = 0

    for site in sites:
        if not isinstance(site, dict) or "name" not in site:
            rep.fail("config", "site-parse", f"Invalid site entry: {site!r}")
            continue

        site_name = normalize_hostname(site["name"])
        if site_filter and site_name != site_filter:
            continue

        if do_routers:
            for router in site.get("routers", []) or []:
                if not isinstance(router, dict):
                    rep.fail(
                        site_name, "router-parse", f"Invalid router entry: {router!r}"
                    )
                    if args.fail_fast:
                        rep.print()
                        return 2
                    continue
                reconcile_router(router, rep)
                processed += 1
                if args.limit and processed >= args.limit:
                    break

        if args.limit and processed >= args.limit:
            break

        if do_hosts:
            for host in site.get("hosts", []) or []:
                if not isinstance(host, dict) or "hostname" not in host:
                    rep.fail(site_name, "host-parse", f"Invalid host entry: {host!r}")
                    if args.fail_fast:
                        rep.print()
                        return 2
                    continue

                hn = normalize_hostname(host.get("hostname", ""))
                fqdn = normalize_hostname(host.get("fqdn", ""))
                if host_filter:
                    if host_filter not in (hn, fqdn):
                        continue
                # If --host is given without --site and user used short name, skip ambiguous matches
                if (
                    args.host
                    and not args.site
                    and host_filter == hn
                    and fqdn
                    and fqdn != host_filter
                ):
                    continue

                reconcile_host(ssh, cfg, site, host, rep, root_pem, ssh_user_ca_pub)
                processed += 1
                if args.fail_fast and any(x.severity == "FAIL" for x in rep.items):
                    rep.print()
                    return 2
                if args.limit and processed >= args.limit:
                    break

        if args.limit and processed >= args.limit:
            break

    rep.print()
    i, w, f = rep.summarize()
    print(f"\nSummary: INFO={i} WARN={w} FAIL={f}")
    return 2 if f > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
