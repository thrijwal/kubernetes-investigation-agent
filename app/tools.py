# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tools for parsing Kubernetes logs and detecting root-cause failure signatures."""

import pathlib
import re
import subprocess
from typing import Any

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
SAMPLE_LOGS_DIR = PROJECT_ROOT / "sample_logs"
ALLOWED_EXTENSIONS = {".log", ".txt", ".json", ".out"}
BLOCKED_FILENAMES = {".env", ".env.example", "credentials.json", "id_rsa"}
K8S_NAME_REGEX = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")

TIMESTAMP_REGEX = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|"
    r"[IWEF]\d{4}\s+\d{2}:\d{2}:\d{2}\.\d+|"
    r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)

SEVERITY_PATTERNS = [
    (
        "FATAL",
        re.compile(
            r"\b(FATAL|CRITICAL|PANIC|EMERG|OOMKilled)\b|^F\d{4}\b", re.IGNORECASE
        ),
    ),
    (
        "ERROR",
        re.compile(
            r"\b(ERROR|ERR|EXCEPTION|FAIL|FAILED|BackOff|CrashLoopBackOff|ErrImagePull|ImagePullBackOff|CreateContainerConfigError|Evicted|Forbidden)\b|^E\d{4}\b",
            re.IGNORECASE,
        ),
    ),
    (
        "WARNING",
        re.compile(
            r"\b(WARN|WARNING|Unhealthy|Back-off|Killing)\b|^W\d{4}\b", re.IGNORECASE
        ),
    ),
    (
        "INFO",
        re.compile(
            r"\b(INFO|Normal|Pulling|Pulled|Created|Started|Scheduled)\b|^I\d{4}\b",
            re.IGNORECASE,
        ),
    ),
]

ENTITY_PATTERNS = {
    "pods": re.compile(
        r"(?:Pod|pod|pods)[/:\s=\"']+([a-z0-9](?:[-a-z0-9]*[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]*[a-z0-9])?)*)",
        re.IGNORECASE,
    ),
    "namespaces": re.compile(
        r"(?:Namespace|namespace|ns)[/:\s=\"']+([a-z0-9](?:[-a-z0-9]*[a-z0-9])?)",
        re.IGNORECASE,
    ),
    "containers": re.compile(
        r"(?:Container|container)[/:\s=\"']+([a-z0-9](?:[-a-z0-9]*[a-z0-9])?)",
        re.IGNORECASE,
    ),
    "exit_codes": re.compile(
        r"(?:Exit Code|exit code|exit status|exit_code)[/:\s=]+(\d+)",
        re.IGNORECASE,
    ),
    "images": re.compile(
        r"(?:image|Image)[/:\s=\"']+([a-zA-Z0-9._/-]+:[a-zA-Z0-9._-]+)"
    ),
}

K8S_FAILURE_SIGNATURES: list[dict[str, Any]] = [
    {
        "id": "oom_killed",
        "category": "OOMKilled / Container Memory Exhaustion",
        "severity": "critical",
        "is_root_cause": True,
        "regex": re.compile(
            r"(OOMKilled|Out of memory|Memory cgroup out of memory|oom-kill|oom_kill_process|"
            r"Exit Code:\s*137|exit code 137|exit status 137|Killed process \d+|"
            r"java\.lang\.OutOfMemoryError|MemoryError|Cannot allocate memory|ENOMEM)",
            re.IGNORECASE,
        ),
        "description": (
            "The container exceeded its configured Kubernetes memory limit (or node memory) "
            "and was terminated by the Linux kernel OOM killer with SIGKILL (Exit Code 137)."
        ),
        "recommended_actions": [
            "Inspect pod resource limits and previous termination state: `kubectl describe pod <pod-name> -n <namespace>`",
            "Increase `resources.limits.memory` and `resources.requests.memory` in the Deployment/Pod spec if workload growth is expected.",
            "Profile the application for memory leaks or unbounded caches/buffers, and configure runtime heap bounds (e.g., `GOMEMLIMIT`, `JVM -Xmx`, or Python worker recycling).",
        ],
    },
    {
        "id": "config_or_secret_error",
        "category": "CreateContainerConfigError / Missing Secret or ConfigMap",
        "severity": "critical",
        "is_root_cause": True,
        "regex": re.compile(
            r"(CreateContainerConfigError|secret\s+\"[^\"]+\"\s+not found|"
            r"configmap\s+\"[^\"]+\"\s+not found|couldn't find key\s+\S+\s+in (?:Secret|ConfigMap)|"
            r"MountVolume\.SetUp failed for volume .* (?:secret|configmap) .* not found)",
            re.IGNORECASE,
        ),
        "description": (
            "Kubelet cannot start the container because a referenced Secret, ConfigMap, "
            "or specific key within them does not exist in the target namespace."
        ),
        "recommended_actions": [
            "Verify whether the missing Secret or ConfigMap exists in the pod's namespace: `kubectl get secrets,configmaps -n <namespace>`",
            "Check the exact keys inside the Secret/ConfigMap: `kubectl describe secret <name> -n <namespace>` or `kubectl describe configmap <name> -n <namespace>`",
            "Create or sync the missing Secret/ConfigMap, or mark the reference as `optional: true` if non-critical.",
        ],
    },
    {
        "id": "image_pull_failure",
        "category": "ImagePullBackOff / ErrImagePull",
        "severity": "critical",
        "is_root_cause": True,
        "regex": re.compile(
            r"(ImagePullBackOff|ErrImagePull|Failed to pull image|manifest for .* not found|"
            r"rpc error: code = NotFound|pull access denied|unauthorized: authentication required|"
            r"Back-off pulling image)",
            re.IGNORECASE,
        ),
        "description": (
            "Kubelet failed to pull the container image due to a non-existent image tag/repository, "
            "missing/expired `imagePullSecrets`, or container registry network/auth errors."
        ),
        "recommended_actions": [
            "Verify the exact image repository and tag in the Pod/Deployment spec: `kubectl get pod <pod-name> -n <namespace> -o jsonpath='{.spec.containers[*].image}'`",
            "Confirm the image tag exists in the container registry.",
            "Verify `imagePullSecrets` are configured on the Pod or ServiceAccount and have valid registry credentials.",
        ],
    },
    {
        "id": "network_or_dependency_failure",
        "category": "Upstream Dependency / Network / DNS Failure",
        "severity": "high",
        "is_root_cause": True,
        "regex": re.compile(
            r"(connection refused|dial tcp .* connect:|i/o timeout|context deadline exceeded|"
            r"no such host|Temporary failure in name resolution|Could not resolve host|"
            r"ECONNREFUSED|ETIMEDOUT|ENOTFOUND|upstream connect error| FATAL: .* database|"
            r"OperationalError: could not connect to server|connection pool exhausted|"
            r"too many clients already|SQLSTATE=53300|remaining connection slots are reserved|"
            r"connection acquisition timeout|Database pool saturated)",
            re.IGNORECASE,
        ),
        "description": (
            "The application failed to connect to an upstream service, database, or DNS endpoint "
            "(e.g., connection refused, timeout, or CoreDNS resolution failure)."
        ),
        "recommended_actions": [
            "Check if the target Service and its backing Endpoints are ready: `kubectl get svc,endpoints -n <namespace>`",
            "Verify the upstream database or dependent pod is running and listening on the expected port.",
            "Inspect NetworkPolicies that might block ingress/egress traffic between pods, and verify CoreDNS pods in `kube-system`.",
        ],
    },
    {
        "id": "probe_failure",
        "category": "Liveness / Readiness / Startup Probe Failure",
        "severity": "high",
        "is_root_cause": False,
        "regex": re.compile(
            r"(Liveness probe failed|Readiness probe failed|Startup probe failed|"
            r"HTTP probe failed with statuscode|TCP probe failed|"
            r"Container .* failed (?:liveness|readiness|startup) probe)",
            re.IGNORECASE,
        ),
        "description": (
            "Kubelet health checks (liveness, readiness, or startup probes) failed. "
            "Readiness failures remove the pod from Service endpoints; liveness/startup failures trigger container restarts."
        ),
        "recommended_actions": [
            "Check if the probe failure is caused by an upstream dependency outage (e.g., DB connection refused) or slow application startup.",
            "Review probe `initialDelaySeconds`, `timeoutSeconds`, `periodSeconds`, and `failureThreshold` in the Pod spec.",
            "Ensure liveness probes do not depend on external downstream services (use readiness probes for external dependencies instead).",
        ],
    },
    {
        "id": "rbac_permission_error",
        "category": "RBAC / Filesystem Permission Denied",
        "severity": "high",
        "is_root_cause": True,
        "regex": re.compile(
            r"(Forbidden|User \"system:serviceaccount:[^\"]+\" cannot|"
            r"cannot (?:get|list|watch|create|update|patch|delete) resource|"
            r"PermissionError|EACCES: permission denied|permission denied)",
            re.IGNORECASE,
        ),
        "description": (
            "The workload encountered a Kubernetes API RBAC authorization error (`403 Forbidden`) "
            "or a container filesystem permission denied error (`EACCES`)."
        ),
        "recommended_actions": [
            "For Kubernetes API `Forbidden` errors, verify the Pod's `serviceAccountName` and inspect `Role`/`ClusterRole` and `RoleBinding`/`ClusterRoleBinding`: `kubectl auth can-i <verb> <resource> --as=system:serviceaccount:<ns>:<sa>`",
            "For filesystem permission errors, check container `securityContext` (`runAsUser`, `runAsGroup`, `fsGroup`) and volume mount permissions.",
        ],
    },
    {
        "id": "storage_or_volume_error",
        "category": "Storage / Volume Mount / Disk Exhaustion Failure",
        "severity": "high",
        "is_root_cause": True,
        "regex": re.compile(
            r"(FailedAttachVolume|FailedMount|Multi-Attach error for volume|"
            r"unbound immediate PersistentVolumeClaims|no persistent volumes available|"
            r"no space left on device|ENOSPC|Read-only file system)",
            re.IGNORECASE,
        ),
        "description": (
            "Pod volume attachment/mounting failed, PersistentVolumeClaim (PVC) remained unbound, "
            "or the container/node exhausted available disk space."
        ),
        "recommended_actions": [
            "Inspect PVC and PV status: `kubectl get pvc,pv -n <namespace>` and `kubectl describe pvc <pvc-name> -n <namespace>`",
            "For `Multi-Attach error`, ensure `ReadWriteOnce` volumes are not mounted by pods scheduled on different nodes simultaneously (e.g., use `Recreate` deployment strategy or StatefulSet).",
            "For `no space left on device`, check ephemeral-storage limits or volume capacity usage.",
        ],
    },
    {
        "id": "scheduling_or_node_pressure",
        "category": "Pod Scheduling Failure / Node Resource Pressure / Eviction",
        "severity": "high",
        "is_root_cause": True,
        "regex": re.compile(
            r"(FailedScheduling|Insufficient cpu|Insufficient memory|"
            r"0/\d+ nodes are available|had untolerated taint|"
            r"The node was low on resource|DiskPressure|MemoryPressure|PIDPressure|Evicted)",
            re.IGNORECASE,
        ),
        "description": (
            "The Kubernetes scheduler could not place the pod on any node due to insufficient CPU/memory, "
            "taints/affinity rules, or the kubelet evicted the pod due to node resource pressure."
        ),
        "recommended_actions": [
            "Check node capacity and allocatable resources: `kubectl describe nodes`",
            "Review pod resource `requests`, `nodeSelector`, `affinity`, and `tolerations`.",
            "If evicted due to `DiskPressure` or `MemoryPressure`, inspect node-level resource consumers or scale the node pool.",
        ],
    },
    {
        "id": "application_crash_or_exception",
        "category": "Application Runtime Crash / Unhandled Exception",
        "severity": "high",
        "is_root_cause": True,
        "regex": re.compile(
            r"(panic:|Traceback \(most recent call last\)|UnhandledPromiseRejection|"
            r"Segmentation fault|SIGSEGV|SIGABRT|SyntaxError|ReferenceError|"
            r"KeyError:|ValueError:|NullPointerException|Exit Code:\s*(?!0\b|137\b)\d+|"
            r"exit status (?!0\b|137\b)\d+)",
            re.IGNORECASE,
        ),
        "description": (
            "The application process terminated with a non-zero exit code due to an unhandled runtime exception, "
            "panic, segmentation fault, or invalid configuration."
        ),
        "recommended_actions": [
            "Fetch logs from the previous crashed container instance: `kubectl logs <pod-name> -n <namespace> --previous`",
            "Inspect the stack trace or error message right before process exit to fix the application bug or missing environment variable.",
        ],
    },
    {
        "id": "crash_loop_backoff",
        "category": "CrashLoopBackOff (Restart Loop Symptom)",
        "severity": "high",
        "is_root_cause": False,
        "regex": re.compile(
            r"(CrashLoopBackOff|Back-off restarting failed container|Error syncing pod)",
            re.IGNORECASE,
        ),
        "description": (
            "`CrashLoopBackOff` indicates Kubernetes is repeatedly restarting a container that keeps exiting. "
            "Note: `CrashLoopBackOff` is a symptom, not the underlying root cause—look at the preceding exit code, "
            "OOMKilled event, probe failure, or application exception to identify why the container exited."
        ),
        "recommended_actions": [
            "Examine the underlying container exit code and termination reason (`OOMKilled`, application exception, or failed liveness probe).",
            "Check previous container logs: `kubectl logs <pod-name> -n <namespace> --previous`",
        ],
    },
]


def parse_kubernetes_logs(log_text: str) -> dict[str, Any]:
    """Parses raw Kubernetes logs into structured entries, severity counts, entities, and a timeline.

    Args:
        log_text: Raw multi-line Kubernetes container logs, event logs, or kubectl describe output.

    Returns:
        Dictionary containing line counts, severity counts, detected entities (pods, namespaces,
        containers, exit codes, images), verbatim error/warning log lines, and a chronological timeline.
    """
    if not log_text or not log_text.strip():
        return {
            "status": "empty_input",
            "message": "No log text was provided.",
            "total_lines": 0,
        }

    raw_lines = log_text.splitlines()
    severity_counts = {"FATAL": 0, "ERROR": 0, "WARNING": 0, "INFO": 0, "OTHER": 0}
    entities: dict[str, set[str]] = {
        "pods": set(),
        "namespaces": set(),
        "containers": set(),
        "exit_codes": set(),
        "images": set(),
    }
    error_and_warning_lines: list[dict[str, Any]] = []
    timeline: list[dict[str, Any]] = []

    stopwords = {
        "the",
        "and",
        "for",
        "with",
        "from",
        "failed",
        "error",
        "in",
        "on",
        "to",
        "is",
        "of",
        "by",
        "status",
        "state",
    }

    for idx, line in enumerate(raw_lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue

        ts_match = TIMESTAMP_REGEX.search(stripped)
        timestamp = ts_match.group(1) if ts_match else None

        detected_severity = "OTHER"
        for sev_name, sev_regex in SEVERITY_PATTERNS:
            if sev_regex.search(stripped):
                detected_severity = sev_name
                break
        severity_counts[detected_severity] += 1

        for entity_key, pattern in ENTITY_PATTERNS.items():
            for match in pattern.finditer(stripped):
                val = match.group(1).strip("\"'.,;()")
                if val and val.lower() not in stopwords and len(val) > 1:
                    entities[entity_key].add(val)

        if detected_severity in ("FATAL", "ERROR", "WARNING"):
            entry = {
                "line_number": idx,
                "timestamp": timestamp,
                "severity": detected_severity,
                "raw_line": stripped,
            }
            error_and_warning_lines.append(entry)
            timeline.append(entry)
        elif timestamp and len(timeline) < 50:
            timeline.append(
                {
                    "line_number": idx,
                    "timestamp": timestamp,
                    "severity": detected_severity,
                    "raw_line": stripped,
                }
            )

    return {
        "status": "success",
        "total_lines": len(raw_lines),
        "non_empty_lines": sum(1 for line in raw_lines if line.strip()),
        "severity_counts": severity_counts,
        "detected_entities": {k: sorted(v) for k, v in entities.items()},
        "error_and_warning_lines": error_and_warning_lines[:100],
        "timeline": timeline[:60],
    }


def detect_k8s_failure_patterns(log_text: str) -> dict[str, Any]:
    """Scans Kubernetes logs against known failure signatures and extracts verbatim supporting evidence.

    Args:
        log_text: Raw multi-line Kubernetes container logs, event logs, or kubectl describe output.

    Returns:
        Dictionary containing matched failure signatures, verbatim supporting log evidence with line
        numbers, prioritized root-cause suspects vs. cascading symptoms, and remediation actions.
    """
    if not log_text or not log_text.strip():
        return {
            "status": "empty_input",
            "matched_patterns": [],
            "primary_root_cause_suspects": [],
            "cascading_symptoms": [],
        }

    raw_lines = log_text.splitlines()
    matched_patterns: list[dict[str, Any]] = []

    for sig in K8S_FAILURE_SIGNATURES:
        evidence: list[dict[str, Any]] = []
        for idx, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            if sig["regex"].search(stripped):
                evidence.append(
                    {
                        "line_number": idx,
                        "raw_line": stripped,
                    }
                )
        if evidence:
            matched_patterns.append(
                {
                    "id": sig["id"],
                    "category": sig["category"],
                    "severity": sig["severity"],
                    "is_root_cause": sig["is_root_cause"],
                    "description": sig["description"],
                    "match_count": len(evidence),
                    "supporting_evidence": evidence[:25],
                    "recommended_actions": sig["recommended_actions"],
                }
            )

    primary_root_causes = [
        p["category"] for p in matched_patterns if p["is_root_cause"]
    ]
    cascading_symptoms = [
        p["category"] for p in matched_patterns if not p["is_root_cause"]
    ]

    # If only symptoms (e.g., probe failure or CrashLoopBackOff) matched without a deeper
    # signature, promote them so the investigator still has a primary suspect.
    if not primary_root_causes and cascading_symptoms:
        primary_root_causes = list(cascading_symptoms)

    return {
        "status": "success",
        "patterns_detected_count": len(matched_patterns),
        "primary_root_cause_suspects": primary_root_causes,
        "cascading_symptoms": cascading_symptoms,
        "matched_patterns": matched_patterns,
    }


def read_log_file(file_path: str) -> dict[str, Any]:
    """Reads a local Kubernetes log file from the project workspace for investigation.

    Args:
        file_path: Relative or absolute path to a local .log, .txt, .json, or .out file inside the workspace.

    Returns:
        Dictionary containing status, resolved path, line count, and full text content of the log file.
    """
    if not file_path or not file_path.strip():
        return {"status": "error", "error": "file_path must not be empty."}

    cleaned = file_path.strip()
    candidate = pathlib.Path(cleaned)
    if not candidate.is_absolute():
        candidate = (PROJECT_ROOT / candidate).resolve()
    else:
        candidate = candidate.resolve()

    try:
        candidate.relative_to(PROJECT_ROOT)
    except ValueError:
        return {
            "status": "error",
            "error": (
                f"Access denied: '{file_path}' is outside the project workspace directory."
            ),
        }

    if candidate.name in BLOCKED_FILENAMES or candidate.name.startswith(".env"):
        return {
            "status": "error",
            "error": f"Access denied: '{candidate.name}' is a restricted file.",
        }

    if candidate.suffix.lower() not in ALLOWED_EXTENSIONS:
        return {
            "status": "error",
            "error": (
                f"Unsupported file extension '{candidate.suffix}'. "
                f"Allowed extensions: {sorted(ALLOWED_EXTENSIONS)}"
            ),
        }

    if not candidate.exists() or not candidate.is_file():
        return {
            "status": "error",
            "error": f"Log file not found: '{file_path}'",
        }

    content = candidate.read_text(encoding="utf-8", errors="replace")
    return {
        "status": "success",
        "file_path": str(candidate.relative_to(PROJECT_ROOT)),
        "line_count": len(content.splitlines()),
        "content": content,
    }


def get_pod_logs(
    pod_name: str,
    namespace: str = "default",
    container: str = "",
    tail_lines: int = 200,
    previous: bool = False,
) -> dict[str, Any]:
    """Fetches logs for a specific Kubernetes pod via `kubectl logs`, falling back to local log files in `sample_logs/` when no cluster is reachable.

    Args:
        pod_name: Name (or prefix) of the Kubernetes pod to fetch logs for (e.g., 'checkout-api-7d9f6b8c7f-x2k9m').
        namespace: Kubernetes namespace of the pod (defaults to 'default').
        container: Optional container name within the pod if the pod has multiple containers.
        tail_lines: Maximum number of recent log lines to return (defaults to 200).
        previous: If True, fetches logs from the previous terminated container instance (`kubectl logs --previous`).

    Returns:
        Dictionary containing status, source ('kubectl' or 'local_sample_logs_fallback'), pod metadata, line count, and raw log text.
    """
    if not pod_name or not pod_name.strip():
        return {"status": "error", "error": "pod_name must not be empty."}

    clean_pod = pod_name.strip()
    clean_ns = (namespace or "default").strip() or "default"
    clean_container = (container or "").strip()
    clamped_tail = max(1, min(int(tail_lines) if tail_lines else 200, 5000))

    if not K8S_NAME_REGEX.match(clean_pod):
        return {
            "status": "error",
            "error": f"Invalid pod_name '{clean_pod}'. Must contain only alphanumeric characters, '-', '_', or '.'.",
        }
    if not K8S_NAME_REGEX.match(clean_ns):
        return {
            "status": "error",
            "error": f"Invalid namespace '{clean_ns}'. Must contain only alphanumeric characters, '-', '_', or '.'.",
        }
    if clean_container and not K8S_NAME_REGEX.match(clean_container):
        return {
            "status": "error",
            "error": f"Invalid container name '{clean_container}'. Must contain only alphanumeric characters, '-', '_', or '.'.",
        }

    # 1. Attempt to fetch logs from a live Kubernetes cluster via `kubectl logs`
    kubectl_cmd = [
        "kubectl",
        "logs",
        clean_pod,
        "-n",
        clean_ns,
        f"--tail={clamped_tail}",
    ]
    if clean_container:
        kubectl_cmd.extend(["-c", clean_container])
    if previous:
        kubectl_cmd.append("--previous")

    kubectl_error = ""
    try:
        proc = subprocess.run(
            kubectl_cmd,
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            log_text = proc.stdout.strip()
            return {
                "status": "success",
                "source": "kubectl",
                "pod_name": clean_pod,
                "namespace": clean_ns,
                "container": clean_container or None,
                "line_count": len(log_text.splitlines()),
                "logs": log_text,
            }
        kubectl_error = (
            proc.stderr.strip() or f"kubectl exited with code {proc.returncode}"
        )
    except FileNotFoundError:
        kubectl_error = "kubectl binary not found on system PATH."
    except subprocess.TimeoutExpired:
        kubectl_error = "kubectl command timed out connecting to the cluster."
    except OSError as exc:
        kubectl_error = f"kubectl execution error: {exc}"

    # 2. Automatic fallback: search local log files in `sample_logs/`
    available_pods: set[str] = set()
    pod_lower = clean_pod.lower()

    if SAMPLE_LOGS_DIR.exists() and SAMPLE_LOGS_DIR.is_dir():
        for log_file in sorted(SAMPLE_LOGS_DIR.iterdir()):
            if (
                not log_file.is_file()
                or log_file.suffix.lower() not in ALLOWED_EXTENSIONS
            ):
                continue

            raw_content = log_file.read_text(encoding="utf-8", errors="replace")
            raw_lines = [
                line
                for line in raw_content.splitlines()
                if line.strip()
                and not line.strip().startswith("cat >")
                and line.strip() != "EOF"
            ]

            file_pods = {
                m.lower() for m in ENTITY_PATTERNS["pods"].findall(raw_content) if m
            }
            available_pods.update(file_pods)

            # Check if the requested pod name matches this log file
            pod_matched_in_file = any(
                pod_lower == fp or pod_lower in fp or fp in pod_lower
                for fp in file_pods
            ) or (pod_lower in raw_content.lower())

            if pod_matched_in_file:
                filtered_lines: list[str] = []
                for line in raw_lines:
                    line_pods = [
                        m.lower() for m in ENTITY_PATTERNS["pods"].findall(line) if m
                    ]
                    # Include lines that belong to the target pod or shared context lines
                    # that do not explicitly reference a different pod.
                    if not line_pods or any(
                        pod_lower == lp or pod_lower in lp or lp in pod_lower
                        for lp in line_pods
                    ):
                        filtered_lines.append(line)

                selected = (filtered_lines or raw_lines)[-clamped_tail:]
                return {
                    "status": "success",
                    "source": "local_sample_logs_fallback",
                    "matched_file": str(log_file.relative_to(PROJECT_ROOT)),
                    "pod_name": clean_pod,
                    "namespace": clean_ns,
                    "container": clean_container or None,
                    "kubectl_fallback_reason": kubectl_error,
                    "line_count": len(selected),
                    "logs": "\n".join(selected),
                }

    return {
        "status": "error",
        "pod_name": clean_pod,
        "namespace": clean_ns,
        "kubectl_error": kubectl_error,
        "available_local_pods": sorted(available_pods),
        "error": (
            f"Could not fetch logs for pod '{clean_pod}' in namespace '{clean_ns}' via kubectl "
            f"({kubectl_error}) and no matching pod logs were found in 'sample_logs/'."
        ),
    }
