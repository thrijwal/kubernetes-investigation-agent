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
"""Unit tests for deterministic Kubernetes log parsing and failure detection tools."""

from unittest.mock import MagicMock, patch

from app.tools import (
    detect_k8s_failure_patterns,
    get_pod_logs,
    parse_kubernetes_logs,
    read_log_file,
)


def test_parse_kubernetes_logs_extracts_entities_and_severity() -> None:
    sample = (
        "2026-10-20T10:14:09.112Z FATAL [kernel] Memory cgroup out of memory: Killed process 18422\n"
        "2026-10-20T10:14:10.015Z Normal Killing Pod/order-processor-7d8f9c6b5-x9k2m "
        "State: Terminated, Reason: OOMKilled, Exit Code: 137\n"
        "2026-10-20T10:14:12.330Z Warning BackOff Pod/order-processor-7d8f9c6b5-x9k2m "
        "Back-off restarting failed container order-worker in pod order-processor-7d8f9c6b5-x9k2m_prod-commerce (CrashLoopBackOff)"
    )
    result = parse_kubernetes_logs(sample)
    assert result["status"] == "success"
    assert result["total_lines"] == 3
    assert result["severity_counts"]["FATAL"] >= 1
    assert "137" in result["detected_entities"]["exit_codes"]
    assert len(result["error_and_warning_lines"]) >= 2
    assert len(result["timeline"]) == 3


def test_detect_k8s_failure_patterns_prioritizes_root_cause_over_symptom() -> None:
    sample = (
        "2026-10-20T10:14:10.015Z Normal Killing Pod/order-processor-7d8f9c6b5-x9k2m "
        "State: Terminated, Reason: OOMKilled, Exit Code: 137\n"
        "2026-10-20T10:14:12.330Z Warning BackOff Pod/order-processor-7d8f9c6b5-x9k2m "
        "Back-off restarting failed container order-worker (CrashLoopBackOff)"
    )
    result = detect_k8s_failure_patterns(sample)
    assert result["status"] == "success"
    assert (
        "OOMKilled / Container Memory Exhaustion"
        in result["primary_root_cause_suspects"]
    )
    assert "CrashLoopBackOff (Restart Loop Symptom)" in result["cascading_symptoms"]
    oom_pattern = next(p for p in result["matched_patterns"] if p["id"] == "oom_killed")
    assert oom_pattern["supporting_evidence"][0]["line_number"] == 1


def test_read_log_file_reads_sample_and_blocks_env() -> None:
    ok = read_log_file("sample_logs/oom_crashloop.log")
    assert ok["status"] == "success"
    assert ok["line_count"] >= 5
    assert "OOMKilled" in ok["content"]

    blocked = read_log_file(".env")
    assert blocked["status"] == "error"

    traversal = read_log_file("../../etc/passwd")
    assert traversal["status"] == "error"


def test_get_pod_logs_uses_kubectl_when_available() -> None:
    mock_proc = MagicMock(
        returncode=0,
        stdout="2026-10-20T10:00:00Z INFO Starting pod\n2026-10-20T10:00:05Z ERROR Crash\n",
        stderr="",
    )
    with patch("app.tools.subprocess.run", return_value=mock_proc) as mock_run:
        res = get_pod_logs(
            pod_name="my-pod-123",
            namespace="production",
            container="api",
            tail_lines=50,
            previous=True,
        )
        assert res["status"] == "success"
        assert res["source"] == "kubectl"
        assert res["pod_name"] == "my-pod-123"
        assert res["line_count"] == 2
        assert "ERROR Crash" in res["logs"]
        mock_run.assert_called_once()


def test_get_pod_logs_falls_back_to_sample_logs_and_validates_names() -> None:
    mock_proc = MagicMock(
        returncode=1,
        stdout="",
        stderr="The connection to the server localhost:8080 was refused",
    )
    with patch("app.tools.subprocess.run", return_value=mock_proc):
        res = get_pod_logs(
            pod_name="checkout-api-7d9f6b8c7f-x2k9m",
            namespace="production",
        )
        assert res["status"] == "success"
        assert res["source"] == "local_sample_logs_fallback"
        assert "SQLSTATE=53300" in res["logs"]

        missing = get_pod_logs(pod_name="nonexistent-pod-9999")
        assert missing["status"] == "error"
        assert len(missing["available_local_pods"]) >= 1

    invalid = get_pod_logs(pod_name="--invalid-flag; rm -rf")
    assert invalid["status"] == "error"
