#!/usr/bin/env python3
"""
KubeSentry Isolation Controller - Production Ready
Monitors Tetragon events and automatically isolates suspicious pods
"""

import json
import time
import os
from datetime import datetime, timedelta
from kubernetes import client, config
import requests
import threading
from collections import defaultdict
import sys

# Configuration
TETRAGON_NAMESPACE = "kubesentry"
ISOLATION_LABEL = "security.kubesentry.io/isolated"
THREAT_THRESHOLD = int(os.getenv("THREAT_THRESHOLD", "3"))
THREAT_WINDOW_SECONDS = int(os.getenv("THREAT_WINDOW_SECONDS", "300"))  # 5 minutes
ISOLATION_DURATION_HOURS = int(os.getenv("ISOLATION_DURATION_HOURS", "24"))
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK", "")

# Initialize Kubernetes client
try:
    config.load_incluster_config()
except config.ConfigException:
    try:
        config.load_kube_config()
    except Exception as e:
        print(f"Failed to load Kubernetes config: {e}", file=sys.stderr)
        sys.exit(1)

v1 = client.CoreV1Api()
networking_v1 = client.NetworkingV1Api()

# Thread-safe threat tracking
threat_events = defaultdict(list)
threat_lock = threading.Lock()

def log(message, level="INFO"):
    """Thread-safe logging"""
    timestamp = datetime.utcnow().isoformat() + "Z"
    print(f"[{timestamp}] [{level}] {message}", flush=True)

def record_threat(key, threat_info):
    """Record threat with timestamp and check threshold"""
    now = datetime.utcnow()
    cutoff = now - timedelta(seconds=THREAT_WINDOW_SECONDS)
    
    with threat_lock:
        # Remove old events outside time window
        threat_events[key] = [
            event for event in threat_events[key] 
            if event['timestamp'] > cutoff
        ]
        
        # Add new event
        threat_events[key].append({
            'timestamp': now,
            'info': threat_info
        })
        
        count = len(threat_events[key])
        should_isolate = count >= THREAT_THRESHOLD
        
        return should_isolate, count

def parse_event(line):
    """Parse Tetragon JSON event"""
    try:
        event = json.loads(line)
        if not isinstance(event, dict):
            return None
        return event
    except (json.JSONDecodeError, ValueError):
        return None

def is_suspicious_event(event):
    """Enhanced threat detection"""
    if not event:
        return False, None
    
    # Handle both process_exec and process_kprobe events
    process = None
    function = None
    
    if "process_kprobe" in event:
        kprobe = event["process_kprobe"]
        function = kprobe.get("function_name", "")
        process = kprobe.get("process", {})
    elif "process_exec" in event:
        exec_event = event["process_exec"]
        process = exec_event.get("process", {})
        function = "process_exec"
    else:
        return False, None
    
    if not process:
        return False, None
    
    # Extract pod information
    pod_info = process.get("pod", {})
    if not pod_info:
        return False, None
    
    pod_name = pod_info.get("name")
    namespace = pod_info.get("namespace", "default")
    
    if not pod_name:
        return False, None
    
    binary = process.get("binary", "")
    
    # Pattern 1: RAW Socket Creation
    if "process_kprobe" in event and function == "__sock_create":
        args = event["process_kprobe"].get("args", [])
        for arg in args:
            if arg.get("int_arg") == 3:  # SOCK_RAW
                return True, {
                    "pod": pod_name,
                    "namespace": namespace,
                    "reason": "RAW_SOCKET_CREATION",
                    "binary": binary,
                    "function": function
                }
    
    # Pattern 2: Suspicious Execution Paths
    suspicious_paths = ["/tmp/", "/dev/shm/", "/var/tmp/", "/proc/self/"]
    if any(binary.startswith(path) for path in suspicious_paths):
        return True, {
            "pod": pod_name,
            "namespace": namespace,
            "reason": "SUSPICIOUS_BINARY_PATH",
            "binary": binary,
            "function": function
        }
    
    # Pattern 3: Known Malware Binaries
    malware_names = ["bpfdoor", "xmrig", "kinsing"]
    if any(malware in binary.lower() for malware in malware_names):
        return True, {
            "pod": pod_name,
            "namespace": namespace,
            "reason": "KNOWN_MALWARE_BINARY",
            "binary": binary,
            "function": function
        }
    
    return False, None

def isolate_pod(pod_name, namespace, reason):
    """Apply isolation with error handling"""
    log(f"ISOLATING: {namespace}/{pod_name} - {reason}", "CRITICAL")
    
    try:
        # Check if pod exists and not already isolated
        pod = v1.read_namespaced_pod(name=pod_name, namespace=namespace)
        
        if pod.metadata.labels and pod.metadata.labels.get(ISOLATION_LABEL) == "true":
            log(f"Pod {namespace}/{pod_name} already isolated", "INFO")
            return True
        
        # Label the pod for isolation
        isolation_time = datetime.utcnow()
        expiry_time = isolation_time + timedelta(hours=ISOLATION_DURATION_HOURS)
        
        label_reason = reason[:63].replace("_", "-").lower()
        
        body = {
            "metadata": {
                "labels": {
                    ISOLATION_LABEL: "true",
                    "security.kubesentry.io/reason": label_reason,
                    "security.kubesentry.io/isolated-at": str(int(isolation_time.timestamp()))
                },
                "annotations": {
                    "security.kubesentry.io/expiry": expiry_time.isoformat(),
                    "security.kubesentry.io/full-reason": reason
                }
            }
        }
        
        v1.patch_namespaced_pod(name=pod_name, namespace=namespace, body=body)
        log(f"Pod labeled: {namespace}/{pod_name}", "INFO")
        
        # Create NetworkPolicy
        create_network_policy(namespace)
        
        # Send notifications
        send_slack_alert(pod_name, namespace, reason, expiry_time)
        
        return True
        
    except client.exceptions.ApiException as e:
        if e.status == 404:
            log(f"Pod {namespace}/{pod_name} not found", "WARNING")
        else:
            log(f"API error: {e}", "ERROR")
        return False
    except Exception as e:
        log(f"Error isolating pod: {e}", "ERROR")
        return False

def create_network_policy(namespace):
    """Create Kubernetes NetworkPolicy"""
    policy_name = "kubesentry-isolation"
    
    policy = client.V1NetworkPolicy(
        api_version="networking.k8s.io/v1",
        kind="NetworkPolicy",
        metadata=client.V1ObjectMeta(
            name=policy_name,
            namespace=namespace
        ),
        spec=client.V1NetworkPolicySpec(
            pod_selector=client.V1LabelSelector(
                match_labels={ISOLATION_LABEL: "true"}
            ),
            policy_types=["Ingress", "Egress"],
            ingress=[],  # Block all ingress
            egress=[
                # Allow DNS only
                client.V1NetworkPolicyEgressRule(
                    to=[
                        client.V1NetworkPolicyPeer(
                            namespace_selector=client.V1LabelSelector(
                                match_labels={"kubernetes.io/metadata.name": "kube-system"}
                            )
                        )
                    ],
                    ports=[
                        client.V1NetworkPolicyPort(protocol="UDP", port=53),
                        client.V1NetworkPolicyPort(protocol="TCP", port=53)
                    ]
                )
            ]
        )
    )
    
    try:
        networking_v1.read_namespaced_network_policy(
            name=policy_name,
            namespace=namespace
        )
        log(f"NetworkPolicy exists in {namespace}", "DEBUG")
    except client.exceptions.ApiException as e:
        if e.status == 404:
            networking_v1.create_namespaced_network_policy(
                namespace=namespace,
                body=policy
            )
            log(f"Created NetworkPolicy in {namespace}", "INFO")

def send_slack_alert(pod_name, namespace, reason, expiry_time):
    """Send Slack notification"""
    if not SLACK_WEBHOOK:
        return
    
    payload = {
        "text": "🚨 *KubeSentry: Pod Isolated*",
        "attachments": [{
            "color": "danger",
            "fields": [
                {"title": "Pod", "value": f"`{pod_name}`", "short": True},
                {"title": "Namespace", "value": f"`{namespace}`", "short": True},
                {"title": "Threat", "value": reason, "short": False},
                {"title": "Action", "value": "Network isolated (DNS only)", "short": True},
                {"title": "Expires", "value": expiry_time.strftime("%Y-%m-%d %H:%M UTC"), "short": True}
            ],
            "footer": "KubeSentry",
            "ts": int(time.time())
        }]
    }
    
    try:
        requests.post(SLACK_WEBHOOK, json=payload, timeout=5)
        log("Slack alert sent", "INFO")
    except Exception as e:
        log(f"Slack failed: {e}", "WARNING")

def monitor_tetragon_logs():
    """Main monitoring loop"""
    log("Starting Tetragon monitor", "INFO")
    
    while True:
        try:
            pods = v1.list_namespaced_pod(
                namespace=TETRAGON_NAMESPACE,
                label_selector="app.kubernetes.io/name=tetragon"
            ).items
            
            if not pods:
                log("No Tetragon pods found", "WARNING")
                time.sleep(30)
                continue
            
            pod_name = pods[0].metadata.name
            log(f"Monitoring: {pod_name}", "INFO")
            
            stream = v1.read_namespaced_pod_log(
                name=pod_name,
                namespace=TETRAGON_NAMESPACE,
                container="tetragon",
                follow=True,
                _preload_content=False,
                timestamps=False
            )
            
            for line in stream:
                try:
                    decoded = line.decode('utf-8').strip()
                    if not decoded:
                        continue
                    
                    event = parse_event(decoded)
                    is_threat, threat_info = is_suspicious_event(event)
                    
                    if is_threat and threat_info:
                        key = f"{threat_info['namespace']}/{threat_info['pod']}"
                        should_isolate, count = record_threat(key, threat_info)
                        
                        log(
                            f"Threat detected: {key} | {threat_info['reason']} | "
                            f"Count: {count}/{THREAT_THRESHOLD}",
                            "WARNING"
                        )
                        
                        if should_isolate:
                            isolate_pod(
                                threat_info['pod'],
                                threat_info['namespace'],
                                threat_info['reason']
                            )
                            # Clear events after isolation
                            with threat_lock:
                                threat_events[key] = []
                
                except Exception as e:
                    log(f"Event processing error: {e}", "ERROR")
                    continue
            
            log("Stream ended, reconnecting...", "WARNING")
            time.sleep(5)
            
        except Exception as e:
            log(f"Monitor error: {e}", "ERROR")
            time.sleep(30)

def cleanup_expired_isolations():
    """Remove isolation from expired pods"""
    log("Starting cleanup thread", "INFO")
    
    while True:
        try:
            time.sleep(3600)  # Check every hour
            
            all_pods = v1.list_pod_for_all_namespaces(
                label_selector=f"{ISOLATION_LABEL}=true"
            ).items
            
            now = datetime.utcnow()
            
            for pod in all_pods:
                annotations = pod.metadata.annotations or {}
                expiry_str = annotations.get("security.kubesentry.io/expiry")
                
                if not expiry_str:
                    continue
                
                try:
                    expiry = datetime.fromisoformat(expiry_str.replace('Z', '+00:00'))
                    if now > expiry.replace(tzinfo=None):
                        log(f"Removing expired isolation: {pod.metadata.namespace}/{pod.metadata.name}", "INFO")
                        
                        v1.patch_namespaced_pod(
                            name=pod.metadata.name,
                            namespace=pod.metadata.namespace,
                            body={
                                "metadata": {
                                    "labels": {
                                        ISOLATION_LABEL: None,
                                        "security.kubesentry.io/reason": None,
                                        "security.kubesentry.io/isolated-at": None
                                    }
                                }
                            }
                        )
                except Exception as e:
                    log(f"Cleanup error for {pod.metadata.name}: {e}", "ERROR")
                    
        except Exception as e:
            log(f"Cleanup thread error: {e}", "ERROR")

def main():
    log("KubeSentry Isolation Controller starting", "INFO")
    log(f"Config: THRESHOLD={THREAT_THRESHOLD}, WINDOW={THREAT_WINDOW_SECONDS}s, DURATION={ISOLATION_DURATION_HOURS}h", "INFO")
    
    # Start cleanup thread
    cleanup_thread = threading.Thread(target=cleanup_expired_isolations, daemon=True)
    cleanup_thread.start()
    
    # Start monitoring
    monitor_tetragon_logs()

if __name__ == "__main__":
    main()
