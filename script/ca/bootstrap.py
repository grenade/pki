#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


def run(cmd: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)


def shquote(s: str) -> str:
    # minimal shell quoting for bash -lc usage
    return "'" + s.replace("'", "'\"'\"'") + "'"


def load_yaml(path: str) -> Dict[str, Any]:
    try:
        import yaml  # type: ignore
    except Exception as ex:
        raise RuntimeError("PyYAML required: python3 -m pip install pyyaml") from ex

    p = Path(path)
    if not p.exists():
        raise RuntimeError(f"Config not found: {p}")
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError("Config root must be a mapping")
    return data


class SSH:
    def __init__(
        self,
        user: str,
        port: int,
        timeout: int,
        proxy_jump: Optional[str],
        dry_run: bool,
    ) -> None:
        self.user = user
        self.port = port
        self.timeout = timeout
        self.proxy_jump = proxy_jump
        self.dry_run = dry_run

    def base(self) -> list[str]:
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
        self, host: str, remote_cmd: str, *, sudo: bool = False, timeout: int = 240
    ) -> Tuple[int, str, str]:
        if sudo:
            remote_cmd = f"sudo -n bash -lc {shquote(remote_cmd)}"
        else:
            remote_cmd = f"bash -lc {shquote(remote_cmd)}"
        full = self.base() + [f"{self.user}@{host}", remote_cmd]
        if self.dry_run:
            print("DRY-RUN SSH:", " ".join(full))
            return 0, "", ""
        cp = run(full, timeout=timeout)
        return cp.returncode, (cp.stdout or "").strip(), (cp.stderr or "").strip()


def b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_repo_file(path: Path, content: str, mode: int = 0o644) -> None:
    ensure_dir(path.parent)
    path.write_text(content, encoding="utf-8")
    os.chmod(path, mode)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument(
        "--ca-host", default=None, help="Override global.ca.token_mint_host"
    )
    ap.add_argument(
        "--ssh-user",
        default=None,
        help="Override reconciliation.ssh.default_user for CA host",
    )
    ap.add_argument("--ssh-port", type=int, default=None)
    ap.add_argument("--proxy-jump", default=None)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--export-assets", action="store_true", default=True)
    ap.add_argument("--no-export-assets", dest="export_assets", action="store_false")
    args = ap.parse_args()

    try:
        cfg = load_yaml(args.config)
        ca_url = cfg["global"]["ca"]["url"]
        ca_host = args.ca_host or cfg["global"]["ca"]["token_mint_host"]
        ca_user = (
            args.ssh_user
            or cfg.get("global", {}).get("ca", {}).get("token_mint_user")
            or cfg.get("reconciliation", {}).get("ssh", {}).get("default_user", "ops")
        )
        ssh_port = int(
            args.ssh_port
            or cfg.get("reconciliation", {}).get("ssh", {}).get("port", 22)
        )
        ssh_timeout = int(
            cfg.get("reconciliation", {})
            .get("ssh", {})
            .get("connect_timeout_seconds", 8)
        )
        proxy_jump = (
            args.proxy_jump
            if args.proxy_jump is not None
            else cfg.get("reconciliation", {}).get("ssh", {}).get("proxy_jump", None)
        )

        # CA DNS names
        # Prefer explicit config if provided; otherwise derive from URL host.
        ca_dns_cfg = cfg.get("global", {}).get("ca", {}).get("dns_names")
        if isinstance(ca_dns_cfg, list) and ca_dns_cfg:
            ca_dns = [str(x) for x in ca_dns_cfg]
        else:
            ca_dns = []
            try:
                from urllib.parse import urlparse

                u = urlparse(ca_url)
                if u.hostname:
                    ca_dns.append(u.hostname)
            except Exception:
                pass

        # Password is a secret: require env var for first init only.
        ca_password = os.environ.get("STEP_CA_PASSWORD", "")

        ssh = SSH(
            user=ca_user,
            port=ssh_port,
            timeout=ssh_timeout,
            proxy_jump=proxy_jump,
            dry_run=args.dry_run,
        )

        # 0) Sanity: reachability
        rc, _, err = ssh.exec(ca_host, "true", sudo=False, timeout=15)
        if rc != 0:
            raise RuntimeError(f"Cannot SSH to CA host {ca_host} as {ca_user}: {err}")

        # 1) Install packages (idempotent)
        install_cmd = r"""
set -euo pipefail

# smallstep repo (idempotent)
if [[ ! -f /etc/yum.repos.d/smallstep.repo ]]; then
  cat > /etc/yum.repos.d/smallstep.repo <<'EOF'
[smallstep]
name=Smallstep
baseurl=https://packages.smallstep.com/stable/fedora/
enabled=1
repo_gpgcheck=0
gpgcheck=1
gpgkey=https://packages.smallstep.com/keys/smallstep-0x889B19391F774443.gpg
EOF
fi

dnf -y makecache
dnf -y install step-ca step-cli openssl jq

# Provide /usr/local/bin/step if Fedora installs it as step-cli (best-effort)
if command -v step-cli >/dev/null 2>&1 && ! command -v step >/dev/null 2>&1; then
  ln -sf "$(command -v step-cli)" /usr/local/bin/step
fi
"""
        rc, out, err = ssh.exec(ca_host, install_cmd, sudo=True, timeout=600)
        if rc != 0:
            raise RuntimeError(f"Package install failed: {err or out}")

        # 2) Initialize CA if needed
        # Use /etc/step-ca as system location.
        # If already initialized, skip.
        init_cmd = f"""
set -euo pipefail

if [[ -f /etc/step-ca/config/ca.json ]]; then
  echo "already-initialized"
  exit 0
fi

if [[ -z {shquote(ca_password)} ]]; then
  echo "STEP_CA_PASSWORD missing (export it before first bootstrap)" >&2
  exit 20
fi

install -d -m 0700 /etc/step-ca/secrets
install -d -m 0755 /etc/step-ca

# password file stays on CA host; never in repo
printf %s {shquote(ca_password)} > /etc/step-ca/secrets/password
chmod 0600 /etc/step-ca/secrets/password

# Initialize with SSH support and bind configured port
# DNS names come from config or derived from URL.
STEPPATH=/etc/step-ca \\
step ca init \\
  --name {shquote(str(cfg.get("global", {}).get("ca", {}).get("name", "internal-ca")))} \\
  --dns {shquote(",".join(ca_dns))} \\
  --address {shquote(f":{int(cfg.get('global', {}).get('ca', {}).get('port', 443))}")} \\
  --provisioner {shquote("bootstrap")} \\
  --password-file /etc/step-ca/secrets/password \\
  --ssh \\
  --deployment-type standalone \\
  --acme

# Move step home to /etc/step-ca (step uses $STEPPATH; we set in service file).
# step ca init will have created config/certs/secrets under the active step path.
# Ensure expected permissions:
chmod -R go-rwx /etc/step-ca/secrets || true
"""
        rc, out, err = ssh.exec(ca_host, init_cmd, sudo=True, timeout=600)
        if rc == 20:
            raise RuntimeError(
                "First bootstrap requires STEP_CA_PASSWORD in your environment."
            )
        if rc != 0:
            raise RuntimeError(f"step ca init failed: {err or out}")

        # 3) Ensure provisioners exist (idempotent)
        # Add the provisioners your scripts assume.
        prov_cmd = f"""
set -euo pipefail
export STEPPATH=/etc/step-ca
export STEP_CA_URL={shquote(ca_url)}

PASS=/etc/step-ca/secrets/password

test -f /etc/step-ca/config/ca.json

ensure_prov () {{
  local name="$1"
  local extra="$2"
  if step ca provisioner list --ca-url "$STEP_CA_URL" --root /etc/step-ca/certs/root_ca.crt | jq -r '.[].name' | grep -Fxq "$name"; then
    echo "provisioner-exists:$name"
  else
    # Create JWK provisioner with minimal defaults.
    # (Policies/templates can be tightened later.)
    step ca provisioner add "$name" --type JWK --create --password-file "$PASS" $extra
    echo "provisioner-added:$name"
  fi
}}

# For host TLS tokens / enrollment
ensure_prov "hosts-jwk" ""

# SSH host cert issuance (your infra scripts call: step ssh certificate --host ...)
ensure_prov "ssh-hosts-jwk" ""

# SSH user cert issuance (workstations)
ensure_prov "ssh-users-jwk" ""
"""
        rc, out, err = ssh.exec(ca_host, prov_cmd, sudo=True, timeout=300)
        if rc != 0:
            raise RuntimeError(f"Provisioner setup failed: {err or out}")

        # 4) systemd service for step-ca (idempotent)
        svc = r"""[Unit]
Description=Smallstep step-ca
After=network-online.target
Wants=network-online.target

[Service]
User=stepca
Group=stepca
Environment=STEPPATH=/etc/step-ca
ExecStart=/usr/bin/step-ca /etc/step-ca/config/ca.json --password-file /etc/step-ca/secrets/password
Restart=on-failure
RestartSec=2s
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"""
        svc_cmd = f"""
set -euo pipefail

# Create dedicated user/group if missing
getent group stepca >/dev/null 2>&1 || groupadd --system stepca
id stepca >/dev/null 2>&1 || useradd --system --home-dir /etc/step-ca --shell /usr/sbin/nologin --gid stepca stepca

chown -R stepca:stepca /etc/step-ca

install -d -m 0755 /etc/systemd/system
tmp="$(mktemp)"
echo {shquote(b64(svc))} | base64 -d > "$tmp"
install -m 0644 "$tmp" /etc/systemd/system/step-ca.service
rm -f "$tmp"

systemctl daemon-reload
systemctl enable --now step-ca.service
"""
        rc, out, err = ssh.exec(ca_host, svc_cmd, sudo=True, timeout=180)
        if rc != 0:
            raise RuntimeError(f"systemd setup failed: {err or out}")

        # 5) Open firewall for CA port (idempotent)
        ca_port = int(cfg.get("global", {}).get("ca", {}).get("port", 443))
        fw_cmd = rf"""
set -euo pipefail
if command -v firewall-cmd >/dev/null 2>&1; then
  firewall-cmd --permanent --add-service=https >/dev/null 2>&1 || true
  firewall-cmd --permanent --add-port={ca_port}/tcp >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || true
fi
"""
        ssh.exec(ca_host, fw_cmd, sudo=True, timeout=60)

        # 6) Export public artifacts into repo (root/issuer + SSH CA pubs)
        if args.export_assets:
            # Paths created by step ca init in STEPPATH
            export_cmd = r"""
set -euo pipefail
export STEPPATH=/etc/step-ca
# Root + intermediate (issuer)
cat /etc/step-ca/certs/root_ca.crt
echo "-----SPLIT-----"
cat /etc/step-ca/certs/intermediate_ca.crt
echo "-----SPLIT-----"
# SSH CA public keys (if present)
# step-ca commonly writes these under /etc/step-ca/certs/
# Names vary slightly; print the most common, ignore missing.
for p in /etc/step-ca/certs/ssh_host_ca_key.pub /etc/step-ca/certs/ssh_user_ca_key.pub; do
  if [[ -f "$p" ]]; then
    cat "$p"
  fi
  echo "-----SPLIT-----"
done
"""
            rc, out, err = ssh.exec(ca_host, export_cmd, sudo=True, timeout=60)
            if rc != 0 or "-----SPLIT-----" not in out:
                raise RuntimeError(f"Export failed: {err or out}")

            parts = out.split("-----SPLIT-----\n")
            if len(parts) < 3:
                raise RuntimeError("Unexpected export format from CA host")

            root_crt = parts[0].strip() + "\n"
            issuer_crt = parts[1].strip() + "\n"
            ssh_host_ca_pub = (parts[2].strip() + "\n") if parts[2].strip() else ""
            ssh_user_ca_pub = (
                (parts[3].strip() + "\n") if len(parts) > 3 and parts[3].strip() else ""
            )

            repo_root = Path(__file__).resolve().parents[2]
            write_repo_file(repo_root / "assets/ca/root-ca-cert.pem", root_crt)
            write_repo_file(repo_root / "assets/ca/issuer-ca-cert.pem", issuer_crt)

            # These are CA pubs; keep them if present
            if ssh_host_ca_pub:
                write_repo_file(
                    repo_root / "assets/ssh/ssh_host_ca.pub", ssh_host_ca_pub
                )
            if ssh_user_ca_pub:
                write_repo_file(
                    repo_root / "assets/ssh/ssh_user_ca.pub", ssh_user_ca_pub
                )

            print("Exported assets into assets/ca/ and assets/ssh/")

        print(f"CA bootstrap complete on {ca_host} (serving {ca_url})")
        return 0

    except Exception as ex:
        eprint(f"ERROR: {ex}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
