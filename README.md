# KubeSentry

**KubeSentry** is a security platform that leverages eBPF (Extended Berkeley Packet Filter) to detect, isolate, and visualize backdoor activities like BPFdoor in real-time within Kubernetes clusters.

## Full Environment and Code Report

A complete technical report based on the server backup in `/home/slee103/hackathon` is available at:

- [`docs/HACKATHON_FULL_REPORT.md`](docs/HACKATHON_FULL_REPORT.md)

The report covers:

- Environment baseline (OS/kernel/runtime)
- Kubernetes namespaces/resources and architecture
- KubeSentry controller code behavior and isolation logic
- Monitoring/logging stack (Tetragon, Prometheus, Loki, Grafana)
- Security handling notes for secrets and backup publication

## Original Files Imported

Original snapshot files requested from the hackathon backup are included under:

- [`original-backup/`](original-backup/)

This includes all exported Kubernetes YAML/JSON files and extracted original controller code.

**Requirements** 

- Kubernetes cluster (v1.24+)
- kubectl configured
- All nodes running Kernel 5.4+
- 3+ nodes require for fully function
- Admin permission requires in every nodes
-[ ] Verify node resources:
  - [ ] CPU per node
  - [ ] Memory per node: (minimum 8GB recommended)
  - [ ] Storage available: (minimum 20GB per node)

  










