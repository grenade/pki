# Infrastructure PKI & SSH Strategy

This repository documents and enforces the **infrastructure-wide certificate and SSH trust strategy** used across all sites, hosts, and management endpoints.

The primary goals are:

- Eliminate long‑lived credentials wherever possible
- Make compromise **time‑bounded**, not catastrophic
- Replace ad‑hoc key sprawl with **central, auditable policy**
- Keep the system *boring*, maintainable, and compatible with existing software

This document is intended to be the **authoritative reference** for how TLS, SSH, and legacy management interfaces (e.g. HPE iLO) are handled.

---

## 1. Design principles

### 1.1 Host‑centric identity

- **Each machine has exactly one canonical identity**
- Identity is independent of application or product domains
- Applications inherit host identity; they do not define it

### 1.2 Central trust, short‑lived credentials

- Trust anchors are few and explicit
- Leaf credentials are short‑lived and automatically renewed
- Loss of a device results in **automatic access expiry**, not emergency rotation

### 1.3 Segregation by site, not by CA

- A **single internal CA** is used
- Logical segregation is encoded in **DNS names and SANs**, not separate CAs

### 1.4 Classical crypto first

- X.509 and SSH use conservative, widely supported algorithms
- Post‑quantum mechanisms are layered **outside** TLS/SSH for now

---

## 2. Site model and naming

Each physical or logical site has:

- A dedicated RFC1918 subnet
- A site‑scoped internal DNS suffix

| Site | Subnet | DNS suffix |
|----|----|----|
| kosherinata | 10.3.0.0/16 | `.kosherinata.internal` |
| hanzalova | 10.6.0.0/16 | `.hanzalova.internal` |
| mitko | 10.9.0.0/16 | `.mitko.internal` |
| ivan | 10.12.0.0/16 | `.ivan.internal` |
| pearl | 10.15.0.0/16 | `.pearl.internal` |
| kazarma | 10.18.0.0/16 | `.kazarma.internal` |

### Canonical host identity

```
<hostname>.<site>.internal
```

Examples:

- `db01.kosherinata.internal`
- `gpu04.mitko.internal`

Bare hostnames (e.g. `db01`) may be included as **secondary SANs** for convenience.

---

## 3. Certificate Authority (Smallstep)

### 3.1 CA overview

- **Smallstep step‑ca**
- Runs on a dedicated control‑plane host
- Binds to **TCP 443** for maximum compatibility

The CA issues:

- X.509 host certificates (TLS)
- SSH host certificates
- SSH user certificates

### 3.2 Trust anchors

| Plane | Trust anchor |
|----|----|
| TLS | Internal X.509 Root CA |
| SSH host auth | SSH Host CA |
| SSH user auth | SSH User CA |

Trust anchors are distributed and validated by this repository’s reconciliation scripts.

---

## 4. TLS (X.509) host certificates

### 4.1 Purpose

Used for:

- HTTPS
- Internal APIs
- mTLS between services
- Databases (e.g. PostgreSQL)

### 4.2 Certificate profile

- One certificate **per host**
- Reused by all applications on that host

**Algorithms**

- ECDSA P‑256 (preferred)
- RSA only for legacy endpoints (e.g. iLO)

**Extended Key Usage**

- `serverAuth`
- `clientAuth`

### 4.3 SAN requirements

Required:

- `DNS:<hostname>.<site>.internal`

Optional:

- `DNS:<hostname>`
- `IP:<stable LAN IP>`

Public domains are **never** included.

### 4.4 File layout (all hosts)

```
/etc/pki/hosts/
├── host-key.pem
├── host-cert.pem
└── ca-chain-cert.pem
```

### 4.5 Lifetime and rotation

| Item | Policy |
|----|----|
| Certificate TTL | 60–90 days |
| Renewal | Daily systemd timer |
| Key rotation | Rare (manual or annual) |

Certificates are replaced atomically and services are reloaded only if content changes.

---

## 5. SSH Certificate Authority

SSH uses **certificates**, not static trusted keys.

### 5.1 SSH host certificates

#### Purpose

- Eliminate TOFU host key warnings
- Make host key rotation safe and routine

#### Trust model

- SSH clients trust the **SSH Host CA**
- Trust is scoped to `*.internal`

#### On servers

- ed25519 host key
- Host key signed by SSH Host CA

#### Rotation

| Item | Policy |
|----|----|
| Host cert TTL | 24–72 hours |
| Renewal | Automated timer |
| Host key rotation | 30–90 days |

Because clients trust the CA, host key rotation is non‑disruptive.

---

### 5.2 SSH user certificates

#### Threat model addressed

- Lost or forgotten laptops
- Old private keys lingering indefinitely

#### Model

- User has a normal ed25519 SSH key
- Access requires a **short‑lived SSH user certificate**
- Servers trust the **SSH User CA**, not individual keys

#### Certificate lifetime

- **4 hours** (default)
- Adjustable to 2 hours if desired

#### Issuance

- Issued locally on the workstation
- Loaded into `ssh-agent`
- No user certs stored on servers

#### Authorization

- `TrustedUserCAKeys` in `sshd_config`
- `AuthorizedPrincipalsFile` used for role control

Loss of a laptop results in automatic access expiry within hours, with no server‑side action required.

---

## 6. Routers (OPNsense)

### 6.1 Role

Routers are **infrastructure endpoints**, not general‑purpose hosts.

- TLS used for management plane only
- SSH used for admin access

### 6.2 TLS strategy

- Where supported, routers receive site‑scoped certificates from the internal CA
- Classical crypto only (RSA/ECDSA, SHA‑256)

Certificates are tracked and validated by reconciliation scripts.

### 6.3 SSH

- Routers fully participate in SSH CA trust
- SSH host certificates are strongly recommended

---

## 7. HPE iLO (Out‑of‑Band Management)

### 7.1 Naming

iLO interfaces use a **separate identity namespace**:

```
ilo-<hostname>.<site>.internal
```

### 7.2 Generation‑based strategy

| Generation | Strategy |
|----|----|
| iLO 5 (Gen10+) | Fully managed certs via internal CA |
| Late iLO 4 (Gen8/9) | Manual/semi‑manual certs, tracked |
| iLO 3 / early 4 | No automation; network containment |

### 7.3 Compensating controls for legacy iLO

- Management VLAN isolation
- VPN or bastion access only
- Strict firewalling
- Pinned or accepted self‑signed certs

Legacy iLOs are **explicitly marked as unmanaged**, but contained.

---

## 8. Post‑quantum considerations

- PQ algorithms are **not** used in X.509 or SSH at this time
- PQ security is provided by:
  - Rosenpass / PQ WireGuard variants
  - Network‑level protection

This avoids breaking legacy software while keeping a clear migration path.

---

## 9. Reconciliation model (this repository)

This repository is the **source of truth**.

Scripts are designed to be run from a trusted workstation over SSH to:

- Validate trust anchors
- Detect configuration drift
- Install missing CA material
- Enable or correct renewal timers
- Warn (not guess) when automation is impossible

**Reconciliation, not configuration drift, is the goal.**

---

## 10. Explicit non‑goals

- Per‑application CAs
- Long‑lived SSH keys
- Implicit trust based on IP or network location
- Perfect security on unfixable legacy firmware

---

## 11. Evolution

This document is expected to evolve.

Changes should:

- Preserve backward compatibility where possible
- Be encoded in scripts, not tribal knowledge
- Prefer explicit containment over fragile automation

If a system cannot be made compliant, it must be **intentionally non‑compliant and documented**.

That clarity is what keeps the infrastructure sane over time.

