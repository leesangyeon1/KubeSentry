# KubeSentry Full Environment and Code Report

This report documents the backup snapshot found at:

- `/home/slee103/hackathon/SERVER-FINAL-BACKUP-20251130-223215`

The goal is to provide a complete technical inventory of environment, settings, structure, and code relevant to the KubeSentry deployment.

## 1) Snapshot Scope

- **Source snapshot date (from backup metadata):** `2025-11-30`
- **Captured host:** `kubesentry-2ca44ce3765a`
- **Captured user:** `root`
- **OS:** Ubuntu 24.04.3 LTS
- **Kernel:** `6.8.0-87-generic`
- **Docker:** `28.2.2`
- **Kubernetes export type:** full cluster object export plus per-namespace object bundles

Top-level snapshot folders:

- `kubernetes/` - cluster and namespace YAML exports
- `system/` - shell profile/history, package inventory, systemd units
- `logs/` - pod logs from all namespaces
- `projects/` - archived server paths (`opt.tar.gz`)
- `secrets/` - environment dump (sensitive values intentionally not replicated here)
- `docker-images/` - image list placeholder
- `databases/` - empty in this snapshot

## 2) Kubernetes Environment

### 2.1 Namespaces

Namespaces exported in `kubernetes/namespaces.json`:

1. `default`
2. `kube-node-lease`
3. `kube-public`
4. `kube-state-metrics`
5. `kube-system`
6. `kubernetes-dashboard`
7. `kubesentry`
8. `loki`
9. `monitoring`

### 2.2 Resource Inventory by Namespace

- `default` (6 objects): ConfigMap(2), Deployment(1), Service(1), ServiceAccount(2)
- `kube-node-lease` (2 objects): ConfigMap(1), ServiceAccount(1)
- `kube-public` (4 objects): ConfigMap(1), Role(1), RoleBinding(1), ServiceAccount(1)
- `kube-state-metrics` (6 objects): ConfigMap(1), Deployment(1), Secret(1), Service(1), ServiceAccount(2)
- `kube-system` (84 objects): ConfigMap(7), DaemonSet(4), Deployment(3), Role(7), RoleBinding(7), Secret(3), Service(7), ServiceAccount(45), StatefulSet(1)
- `kubernetes-dashboard` (36 objects): ConfigMap(4), Deployment(7), Role(3), RoleBinding(3), Secret(5), Service(7), ServiceAccount(7)
- `kubesentry` (19 objects): ConfigMap(3), DaemonSet(1), Deployment(1), Role(1), RoleBinding(1), Secret(6), Service(3), ServiceAccount(3)
- `loki` (17 objects): ConfigMap(3), DaemonSet(1), Role(1), RoleBinding(1), Secret(4), Service(3), ServiceAccount(3), StatefulSet(1)
- `monitoring` (74 objects): ConfigMap(34), DaemonSet(1), Deployment(3), PVC(1), Role(1), RoleBinding(1), Secret(16), Service(8), ServiceAccount(7), StatefulSet(2)

### 2.3 Cluster-Level Exports

Files captured:

- `kubernetes/clusterroles.yaml`
- `kubernetes/clusterrolebindings.yaml`
- `kubernetes/crds.yaml`
- `kubernetes/storageclasses.yaml`
- `kubernetes/persistentvolumes.yaml`

Notable cluster RBAC entries include:

- `ClusterRole` / `ClusterRoleBinding` for `kubesentry-controller` (namespace `default`)
- Tetragon cluster roles and operator roles
- Prometheus operator cluster roles

## 3) KubeSentry Runtime Architecture (as Deployed)

### 3.1 Detection Plane (eBPF)

- Tetragon is deployed in namespace `kubesentry`:
  - `DaemonSet`: `tetragon` (v1.6.0), privileged, host network, BPF mount (`/sys/fs/bpf`)
  - `Deployment`: `tetragon-operator` (v1.6.0)
  - Config and service objects for metrics and control

This provides node-level syscall/process event visibility and exports event logs.

### 3.2 Isolation Plane (Custom Controller)

- Custom controller runs in namespace `default`:
  - `Deployment`: `kubesentry-controller`
  - Container image: `python:3.11-slim`
  - Controller code mounted from ConfigMap `controller-script`
  - ServiceAccount: `kubesentry-controller`

Configuration via env vars:

- `THREAT_THRESHOLD=3`
- `THREAT_WINDOW_SECONDS=300`
- `ISOLATION_DURATION_HOURS=24`
- `SLACK_WEBHOOK` (empty in exported deployment)

### 3.3 Observability Plane

- `monitoring` namespace:
  - Prometheus stack (`kube-prometheus-stack`)
  - Grafana (`docker.io/grafana/grafana:12.3.0`)
- `loki` namespace:
  - Loki (`grafana/loki:2.6.1`)
  - Promtail agents

This forms the metrics + logs visualization backend for KubeSentry operations.

## 4) Code Inventory and Descriptions

The primary custom KubeSentry logic in this snapshot is embedded in:

- `kubernetes/namespaces/default/configmaps.yaml` under key `isolation_controller.py`

### 4.1 `isolation_controller.py` Behavior Summary

Core capabilities implemented in code:

1. **In-cluster Kubernetes API initialization**
   - Loads in-cluster config (falls back to local kubeconfig if needed).

2. **Tetragon log stream consumption**
   - Locates Tetragon pod (`app.kubernetes.io/name=tetragon`) in namespace `kubesentry`.
   - Streams JSON logs from `tetragon` container.

3. **Threat detection rules**
   - Flags suspicious events when:
     - RAW socket creation (`__sock_create` with SOCK_RAW)
     - Binary path starts with `/tmp/`, `/dev/shm/`, `/var/tmp/`, `/proc/self/`
     - Binary name indicates known malware (`bpfdoor`, `xmrig`, `kinsing`)

4. **Temporal threat scoring**
   - Per pod+namespace event tracking in a rolling window.
   - Isolation trigger when threshold is reached.

5. **Pod isolation actions**
   - Labels pod with:
     - `security.kubesentry.io/isolated=true`
     - reason and timestamp labels
   - Creates/ensures a `NetworkPolicy` (`kubesentry-isolation`) that:
     - denies ingress
     - restricts egress to DNS only (UDP/TCP 53 to `kube-system`)

6. **Alerting**
   - Optional Slack webhook notification with pod, namespace, reason, and expiry.

7. **Automatic cleanup**
   - Background thread removes isolation labels when expiry timestamp is reached.

### 4.2 Operational Notes from Logs

From `logs/k8s-default-kubesentry-controller-74c5b7bc49-n2tlf.log`:

- Controller starts successfully and prints effective configuration.
- It continuously reconnects every ~4 hours when stream ends:
  - `Stream ended, reconnecting...`
- Reconnect behavior appears resilient and intentional.

From `logs/k8s-default-bpfdoor-simulator.log`:

- Simulator container reports `BPFdoor Simulator Ready`.

## 5) Host and System Settings

### 5.1 Shell/User Environment

From `system/profile`, `system/bashrc`, and `secrets/environment-variables.txt`:

- Standard Ubuntu root shell profile
- Default interactive bash settings and history policy
- PATH includes standard system binaries and snap path
- No custom project-specific shell aliases for KubeSentry were found in exported bashrc

### 5.2 Package and Runtime Baseline

From `system/pip-packages.txt`:

- Python stack includes automation/ops libraries:
  - `ansible`, `boto3`, `requests`, `PyYAML`, etc.
- `bcc` is present (`0.29.1`) which is relevant to eBPF tooling ecosystems

From `system/npm-packages.txt`:

- no global npm packages captured in this snapshot

### 5.3 Services and Scheduled Jobs

From `system/systemd/arkenstone-consumer.service`:

- Persistent service `arkenstone_consumer` (non-KubeSentry but active on host)

From `system/crontab.txt`:

- Cron entry executes `/opt/vultr/dhcp_renew.sh` every minute

## 6) Archived Project/Host Artifacts

### 6.1 `projects/opt.tar.gz`

- Large archive (~124 MB) containing host `/opt` subtree items:
  - `opt/containerd/`
  - `opt/cni/bin/*`
  - `opt/vultr/*`

This is host runtime infrastructure content, not application source repository code.

### 6.2 Docker and Database Backups

- `docker-images/image-list.txt` exists but is empty in snapshot
- `databases/` directory is empty in snapshot

## 7) Container Image Inventory

Workload images discovered in exported manifests include:

- **KubeSentry / detection:** `quay.io/cilium/tetragon:v1.6.0`, `quay.io/cilium/tetragon-operator:v1.6.0`, `python:3.11-slim`
- **Observability:** `docker.io/grafana/grafana:12.3.0`, `grafana/loki:2.6.1`, `docker.io/grafana/promtail:3.5.1`, Prometheus Operator and Prometheus images
- **Cluster components:** Calico images, CoreDNS, kube-proxy, Vultr CSI, dashboard images

Total unique workload images identified: `34`

## 8) Security and Data Handling Notes

Important: this backup contains potentially sensitive material (environment exports, full secrets YAML, historical command logs).

For public repository publication:

- Do **not** publish raw secret values.
- Do **not** publish complete secret manifests.
- Do **not** publish raw SSH/auth data.
- Prefer redacted metadata (secret names/types only), as done in this report.

## 9) Gaps and Limitations

- `projects/` does not contain a dedicated application source tree; only archived host paths.
- Database dumps are absent.
- Docker image list file is present but empty.
- The authoritative custom logic is currently embedded in Kubernetes ConfigMap export, not a standalone source file in this snapshot.

## 10) Recommended Repository Follow-Ups

To make KubeSentry maintainable as code:

1. Move `isolation_controller.py` into repository source (`src/controller/` or similar).
2. Keep Kubernetes manifests in versioned folders (base + overlays).
3. Add reproducible deployment docs for Tetragon + controller + observability stack.
4. Add security policy for backup/snapshot handling with secret redaction checklist.
5. Add CI validation for YAML linting and controller static checks.

---

Report generated from backup inventory and manifest/log analysis under:

- `/home/slee103/hackathon/SERVER-FINAL-BACKUP-20251130-223215`
