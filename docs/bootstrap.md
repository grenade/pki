# CA Bootstrap Script (`script/ca/bootstrap.py`)

This document explains what `script/ca/bootstrap.py` does and how to use it to bootstrap a Smallstep CA instance for this PKI setup.

## Overview

`script/ca/bootstrap.py` is a Python script that:

1. Connects to a remote CA host over SSH.
2. Installs Smallstep `step-ca` and related tools.
3. Initializes a new CA configuration under `/etc/step-ca` (if not already initialized).
4. Ensures a set of expected provisioners exist.
5. Installs / updates a systemd unit for `step-ca` and starts the service.
6. Optionally opens firewall ports for the CA.
7. Optionally exports public CA artifacts (certs and SSH CA public keys) into this repo.

The script is designed to be **idempotent**: re-running it against the same host should be safe and will skip work that’s already done.

---

## Inputs

### Command-line arguments

- `--config <path>` (required)  
  Path to a YAML config file describing the CA and SSH details (e.g. `config/real.yml`).

- `--ca-host <hostname>` (optional)  
  Override `global.ca.token_mint_host` from the config.

- `--ssh-user <user>` (optional)  
  Override the SSH user used for the CA host. By default it resolves to:

  - `global.ca.token_mint_user`, else
  - `reconciliation.ssh.default_user`, else
  - `"ops"`.

- `--ssh-port <port>` (optional)  
  SSH port to connect to the CA host. Defaults from:

  - `reconciliation.ssh.port`, else
  - `22`.

- `--proxy-jump <host>` (optional)  
  SSH proxy jump (e.g. `bastion.example.com`). Defaults from:

  - `reconciliation.ssh.proxy_jump` if present.

- `--dry-run` (flag)  
  When set, prints the SSH commands that would be executed instead of running them.

- `--export-assets` / `--no-export-assets`  
  Controls whether to export CA public artifacts into `assets/` (default is `--export-assets`).

### Environment variables

- `STEP_CA_PASSWORD` (required on first bootstrap)  
  Password used to protect the CA keys during `step ca init`.  
  For subsequent runs (when the CA is already initialized), the script will work without it.

  Example:

  ```bash
  STEP_CA_PASSWORD=$(pass pki/step-ca/password) \
    script/ca/bootstrap.py --config config/real.yml
  ```

---

## Configuration fields used

The script reads a YAML file and primarily expects:

Under `global.ca`:

- `url`  
  The externally visible CA URL (e.g. `https://ca.example.com`).
- `token_mint_host`  
  Hostname or IP of the CA server to SSH into.
- `token_mint_user` (optional)  
  User to SSH as (can be overridden by `--ssh-user`).
- `port` (optional, default `443`)  
  TCP port where `step-ca` will listen.
- `name` (optional, default `"internal-ca"`)  
  Human-friendly CA name.
- `dns_names` (optional)  
  List of DNS names for the CA certificate; if omitted, the script derives one from the hostname part of `url`.

Under `reconciliation.ssh`:

- `default_user` (optional, fallback for SSH user).
- `port` (optional, default `22`).
- `connect_timeout_seconds` (optional, default `8`).
- `proxy_jump` (optional)  
  SSH `ProxyJump` target.

---

## High-level flow

1. **Load configuration**
2. **Resolve CA host and SSH connection parameters**
3. **Compute CA DNS names from config or CA URL**
4. **Set up SSH helper**
5. **Verify host reachability**
6. **Install Smallstep packages on the CA host**
7. **Initialize the CA (`step ca init`) if not initialized**
8. **Ensure provisioners exist**
9. **Configure and start the `step-ca` systemd service**
10. **Open firewall ports for the CA**
11. **Export public artifacts (root/issuer + SSH CA keys) into the repo**
12. **Print completion message**

The following sections describe each step in more detail.

---

## Step-by-step behavior

### 1. Load configuration

The script:

- Reads the YAML file specified by `--config`.
- Expects the root of the file to be a mapping (dictionary).
- Extracts:

  - `ca_url = cfg["global"]["ca"]["url"]`
  - `ca_host = args.ca_host or cfg["global"]["ca"]["token_mint_host"]`
  - SSH user / port / proxy jump from CLI args or appropriate config fields.

If required keys are missing, you’ll get a `RuntimeError` with a message like “Config not found” or similar.

---

### 2. Resolve CA host and SSH connection parameters

The SSH username is resolved as:

1. `--ssh-user` (if provided),
2. else `global.ca.token_mint_user`,
3. else `reconciliation.ssh.default_user`,
4. else `"ops"`.

The SSH port, timeout, and proxy jump are similarly taken from CLI args or config.

An `SSH` helper class encapsulates these settings and provides:

- A `base()` method to build a standard SSH command (BatchMode, StrictHostKeyChecking, connect timeout, proxy jump).
- An `exec(host, remote_cmd, sudo=False, timeout=...)` method to:
  - wrap `remote_cmd` in `bash -lc` or `sudo -n bash -lc`,
  - run it via `subprocess.run`,
  - return `(exit_code, stdout, stderr)`.

If `--dry-run` is set, it prints the SSH command instead of executing it.

---

### 3. Compute CA DNS names

The script determines DNS names for the CA certificate:

- If `global.ca.dns_names` is a non-empty list, it uses that.
- Otherwise, it attempts to parse `global.ca.url` and take the hostname, e.g.:

  - `https://ca.example.com:8443` → `["ca.example.com"]`

The list is passed to `step ca init` as a comma-separated string.

---

### 4. CA password

The script checks:

- `ca_password = os.environ.get("STEP_CA_PASSWORD", "")`

For the **first** initialization, `STEP_CA_PASSWORD` must be set. If not set and the CA is not yet initialized, the script aborts with:

- `First bootstrap requires STEP_CA_PASSWORD in your environment.`

If the CA is already initialized, the password file is already present on the host, so the script doesn’t attempt to recreate it.

---

### 5. Verify host reachability

Before doing any heavy work, the script runs:

- `ssh.exec(ca_host, "true", sudo=False, timeout=15)`

If this fails, it raises:

- `RuntimeError(f"Cannot SSH to CA host {ca_host} as {ca_user}: {err}")`

This ensures network/SSH connectivity is working before proceeding.

---

### 6. Install Smallstep packages

On the CA host, as `root` (via `sudo`), the script:

1. Ensures a Smallstep repo file at `/etc/yum.repos.d/smallstep.repo` (Fedora-style).
2. Runs:

   - `dnf -y makecache`
   - `dnf -y install step-ca step-cli openssl jq`

3. If Fedora installs the binary as `step-cli` but not `step`, it symlinks:

   - `/usr/local/bin/step` → `$(command -v step-cli)`

If any of this fails, it raises `RuntimeError("Package install failed: ...")`.

---

### 7. Initialize CA (if needed)

Still on the CA host, as `root`, it runs a script that:

1. Checks if `/etc/step-ca/config/ca.json` exists:
   - If it does, prints `"already-initialized"` and exits successfully.

2. If **not** initialized:
   - Verifies that `STEP_CA_PASSWORD` (from the *local* environment) was passed in; if empty, exits with code `20`, which the Python code interprets as:

     - `First bootstrap requires STEP_CA_PASSWORD in your environment.`

   - Creates directories:
     - `/etc/step-ca/secrets` (mode `0700`)
     - `/etc/step-ca` (mode `0755`)

   - Writes `/etc/step-ca/secrets/password` with the provided CA password and sets mode `0600`.

   - Runs `step ca init` with:
     - `STEPPATH=/etc/step-ca`
     - `--name` (from `global.ca.name` or `"internal-ca"`)
     - `--dns` (comma-joined DNS names)
     - `--address` `":<port>"` where port is `global.ca.port` or `443`
     - `--provisioner "bootstrap"`
     - `--password-file /etc/step-ca/secrets/password`
     - `--ssh`
     - `--deployment-type standalone`
     - `--acme`

   - Tightens permissions on `/etc/step-ca/secrets` (best-effort `chmod -R go-rwx`).

If `step ca init` fails, the script raises `RuntimeError("step ca init failed: ...")`.

---

### 8. Ensure provisioners exist

Once the CA is initialized, the script ensures some JWK provisioners exist, by running a shell helper on the CA host:

- It sets:

  - `STEPPATH=/etc/step-ca`
  - `PASS=/etc/step-ca/secrets/password`
  - Expects `/etc/step-ca/config/ca.json` to exist.

- Defines a function:

  ```bash
  ensure_prov () {
    local name="$1"
    local extra="$2"
    if step ca provisioner list --ca-url "$STEP_CA_URL" --root /etc/step-ca/certs/root_ca.crt \
       | jq -r '.[].name' | grep -Fxq "$name"; then
      echo "provisioner-exists:$name"
    else
      step ca provisioner add "$name" --type JWK --create --password-file "$PASS" $extra
      echo "provisioner-added:$name"
    fi
  }
  ```

  > Note: `STEP_CA_URL` is set earlier from the Python `ca_url` variable so that `step` talks to the correct CA endpoint.

- Calls:

  - `ensure_prov "hosts-jwk" ""`
  - `ensure_prov "ssh-hosts-jwk" ""`
  - `ensure_prov "ssh-users-jwk" ""`

If this step fails, the script raises:

- `RuntimeError("Provisioner setup failed: ...")`

---

### 9. systemd service setup

The script constructs a `step-ca` systemd unit:

- Unit file path: `/etc/systemd/system/step-ca.service`
- Runs on the CA host as `root`:

  1. Ensures a `stepca` system user and group exist (system account, no login).
  2. `chown -R stepca:stepca /etc/step-ca`
  3. Writes the unit file, with key parts:

     - `User=stepca`
     - `Group=stepca`
     - `Environment=STEPPATH=/etc/step-ca`
     - `ExecStart=/usr/bin/step-ca /etc/step-ca/config/ca.json --password-file /etc/step-ca/secrets/password`
     - `Restart=on-failure`
     - `AmbientCapabilities=CAP_NET_BIND_SERVICE`
     - `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`
     - `LimitNOFILE=65536`

  4. Runs:

     - `systemctl daemon-reload`
     - `systemctl enable --now step-ca.service`

If this fails, you get:

- `RuntimeError("systemd setup failed: ...")`

---

### 10. Firewall configuration

If `firewall-cmd` is available on the CA host, the script:

- Adds:

  - `--add-service=https`
  - `--add-port=<ca_port>/tcp` where `ca_port` is `global.ca.port` or `443`

- Runs `firewall-cmd --reload`.

Errors here are ignored (best-effort), but any serious failure would cause a non-zero RC from the SSH command.

---

### 11. Export public artifacts

If `--export-assets` is enabled (default), the script:

1. On the CA host (as `root`), with `STEPPATH=/etc/step-ca`, prints:

   - `/etc/step-ca/certs/root_ca.crt`
   - `/etc/step-ca/certs/intermediate_ca.crt`
   - `/etc/step-ca/certs/ssh_host_ca_key.pub` (if present)
   - `/etc/step-ca/certs/ssh_user_ca_key.pub` (if present)

   separated by markers `-----SPLIT-----`.

2. Back on the local machine, it splits the output on `-----SPLIT-----\n`:

   - `root_crt` → `assets/ca/root-ca-cert.pem`
   - `issuer_crt` → `assets/ca/issuer-ca-cert.pem`
   - host/user SSH CA pubs (if present) → `assets/ssh/ssh_host_ca.pub`, `assets/ssh/ssh_user_ca.pub`.

3. Creates directories as needed and writes files with mode `0644`.

If this step fails (e.g. missing certs or output format issues), you see:

- `RuntimeError("Export failed: ...")` or
- `RuntimeError("Unexpected export format from CA host")`.

---

### 12. Completion

If everything succeeds, the script prints:

- `CA bootstrap complete on <ca_host> (serving <ca_url>)`

and exits with code `0`.

On any error, it prints:

- `ERROR: <message>`

to stderr and exits with code `2` (or another code if the error originated from an explicit return).

---

## Typical usage

From the repository root:

```bash
# First bootstrap (requires password for CA key encryption)
STEP_CA_PASSWORD=$(pass pki/step-ca/password) \
  script/ca/bootstrap.py \
    --config config/real.yml

# Subsequent runs (to reconcile / re-export assets)
script/ca/bootstrap.py --config config/real.yml
```

Options:

- Override CA host and SSH user:

  ```bash
  STEP_CA_PASSWORD=$(pass pki/step-ca/password) \
    script/ca/bootstrap.py \
      --config config/real.yml \
      --ca-host ca1.internal.example.com \
      --ssh-user root
  ```

- Disable exporting assets:

  ```bash
  script/ca/bootstrap.py --config config/real.yml --no-export-assets
  ```

- Dry-run (show SSH commands only):

  ```bash
  script/ca/bootstrap.py --config config/real.yml --dry-run
  ```

---

## Notes and assumptions

- The CA host is assumed to be a Fedora/RHEL-style system with `dnf` and `systemd`.
- SSH key-based auth and host reachability must be configured outside this script.
- The script expects to be run from within the repo (uses `__file__` to locate the repo root to write `assets/`).
- The configuration format may evolve; this document reflects the fields currently consumed by `script/ca/bootstrap.py`.