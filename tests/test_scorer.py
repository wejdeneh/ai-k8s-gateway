"""
Unit tests for app/risk/scorer.py

Tests cover:
  - v1 scoring: action weight, namespace weight, resource weight
  - v2 scoring: params inspection (privileged, hostNetwork, image trust, replicas)
  - Boundary conditions: unknown verbs, empty params, read-only ignores params
  - Output type: level (string), score (int), reasons (list of strings)
"""

import pytest

from app.risk.scorer import RiskLevel, score


class TestActionWeights:
    """Action verb → correct base score."""

    @pytest.mark.parametrize(
        "action, expected_score",
        [
            ("get", 0),
            ("list", 0),
            ("watch", 0),
            ("create", 1),
            ("update", 1),
            ("patch", 1),
            ("apply", 1),
            ("delete", 2),
            ("replace", 2),
            ("exec", 2),
        ],
    )
    def test_action_score(self, action: str, expected_score: int) -> None:
        rs = score(action, "pods", "default")
        assert rs.score == expected_score, (
            f"action={action!r} expected score={expected_score}, got {rs.score}"
        )

    def test_unknown_action_scores_one(self) -> None:
        """Unknown verbs default to score 1 (medium risk — be conservative)."""
        rs = score("frobnicate", "pods", "default")
        assert rs.score == 1

    def test_case_insensitive(self) -> None:
        rs_lower = score("delete", "pods", "default")
        rs_upper = score("DELETE", "pods", "default")
        assert rs_lower.score == rs_upper.score == 2


class TestNamespaceWeights:
    """Privileged namespaces add +2."""

    @pytest.mark.parametrize(
        "namespace", ["kube-system", "kube-public", "kube-node-lease"]
    )
    def test_privileged_namespace_adds_two(self, namespace: str) -> None:
        rs = score("list", "pods", namespace)
        assert rs.score == 2, f"Expected 2 for namespace={namespace!r}, got {rs.score}"

    def test_default_namespace_adds_zero(self) -> None:
        rs = score("list", "pods", "default")
        assert rs.score == 0

    def test_custom_namespace_adds_zero(self) -> None:
        rs = score("list", "pods", "my-team-namespace")
        assert rs.score == 0


class TestResourceWeights:
    """Sensitive resources add +1."""

    @pytest.mark.parametrize(
        "resource",
        [
            "secret",
            "secrets",
            "role",
            "roles",
            "rolebinding",
            "rolebindings",
            "clusterrole",
            "clusterroles",
            "clusterrolebinding",
            "clusterrolebindings",
            "serviceaccount",
            "serviceaccounts",
        ],
    )
    def test_sensitive_resource_adds_one(self, resource: str) -> None:
        rs = score("list", resource, "default")
        assert rs.score == 1, f"Expected 1 for resource={resource!r}, got {rs.score}"

    def test_pods_not_sensitive(self) -> None:
        rs = score("list", "pods", "default")
        assert rs.score == 0

    def test_deployments_not_sensitive(self) -> None:
        rs = score("list", "deployments", "default")
        assert rs.score == 0


class TestRiskBands:
    """Score → correct risk band."""

    def test_score_zero_is_low(self) -> None:
        rs = score("list", "pods", "default")
        assert rs.level == RiskLevel.LOW
        assert rs.score == 0

    def test_score_one_is_low(self) -> None:
        rs = score("create", "deployments", "default")
        assert rs.level == RiskLevel.LOW
        assert rs.score == 1

    def test_score_two_is_medium(self) -> None:
        rs = score("delete", "pods", "default")
        assert rs.level == RiskLevel.MEDIUM
        assert rs.score == 2

    def test_score_three_is_medium(self) -> None:
        rs = score("delete", "secrets", "default")  # 2 + 1 = 3
        assert rs.level == RiskLevel.MEDIUM
        assert rs.score == 3

    def test_score_four_plus_is_high(self) -> None:
        rs = score("delete", "pods", "kube-system")  # 2 + 2 = 4
        assert rs.level == RiskLevel.HIGH
        assert rs.score >= 4

    def test_worst_case_is_high(self) -> None:
        rs = score("delete", "secrets", "kube-system")  # 2 + 2 + 1 = 5
        assert rs.level == RiskLevel.HIGH
        assert rs.score == 5


class TestParamsInspection:
    """v2: params dict is inspected on write actions."""

    def test_privileged_true_adds_three(self) -> None:
        rs = score(
            "create",
            "deployments",
            "demo",
            params={"privileged": True, "image": "nginx:alpine"},
        )
        # 1 (create) + 3 (privileged) = 4 → HIGH
        assert rs.score >= 4
        assert rs.level == RiskLevel.HIGH
        assert any("privileged" in r for r in rs.reasons)

    def test_host_network_adds_two(self) -> None:
        rs = score(
            "create",
            "deployments",
            "demo",
            params={"hostNetwork": True, "image": "nginx:alpine"},
        )
        # 1 + 2 = 3 → MEDIUM (still dangerous)
        assert rs.score >= 3
        assert any("hostNetwork" in r for r in rs.reasons)

    def test_host_pid_adds_two(self) -> None:
        rs = score(
            "create", "pods", "demo", params={"hostPID": True, "image": "nginx:alpine"}
        )
        assert rs.score >= 3
        assert any("hostPID" in r for r in rs.reasons)

    def test_untrusted_image_adds_one(self) -> None:
        rs_trusted = score(
            "create", "deployments", "demo", params={"image": "nginx:alpine"}
        )
        rs_untrusted = score(
            "create", "deployments", "demo", params={"image": "cryptominer:latest"}
        )
        assert rs_untrusted.score == rs_trusted.score + 1
        assert any("trusted" in r for r in rs_untrusted.reasons)

    def test_trusted_image_adds_zero(self) -> None:
        for image in ["nginx:alpine", "python:3.11", "gcr.io/myco/app:v1"]:
            rs = score("create", "deployments", "demo", params={"image": image})
            assert rs.score == 1, (
                f"Expected score 1 for trusted image {image!r}, got {rs.score}"
            )

    def test_high_replicas_adds_one(self) -> None:
        rs_normal = score(
            "create",
            "deployments",
            "demo",
            params={"image": "nginx:alpine", "replicas": 3},
        )
        rs_high = score(
            "create",
            "deployments",
            "demo",
            params={"image": "nginx:alpine", "replicas": 50},
        )
        assert rs_high.score == rs_normal.score + 1
        assert any("replicas" in r for r in rs_high.reasons)

    def test_normal_replicas_adds_zero(self) -> None:
        rs = score(
            "create",
            "deployments",
            "demo",
            params={"image": "nginx:alpine", "replicas": 5},
        )
        assert rs.score == 1  # just the create weight

    def test_read_action_ignores_params(self) -> None:
        """Params should NOT be inspected for read-only actions."""
        rs = score(
            "list",
            "pods",
            "default",
            params={"privileged": True, "image": "evil:latest", "replicas": 999},
        )
        assert rs.score == 0
        assert rs.level == RiskLevel.LOW
        assert not any("privileged" in r for r in rs.reasons)

    def test_empty_params_does_not_crash(self) -> None:
        rs = score("create", "deployments", "demo", params={})
        assert rs.score == 1  # just the create weight

    def test_none_params_does_not_crash(self) -> None:
        rs = score("create", "deployments", "demo", params=None)
        assert rs.score == 1


class TestReasons:
    """Reasons list is populated correctly."""

    def test_reasons_is_list_of_strings(self) -> None:
        rs = score("delete", "secrets", "kube-system")
        assert isinstance(rs.reasons, list)
        assert all(isinstance(r, str) for r in rs.reasons)
        assert len(rs.reasons) >= 3  # action + namespace + resource

    def test_action_reason_always_present(self) -> None:
        rs = score("get", "pods", "default")
        assert any("action" in r for r in rs.reasons)

    def test_namespace_reason_present_for_system_ns(self) -> None:
        rs = score("get", "pods", "kube-system")
        assert any("kube-system" in r for r in rs.reasons)

    def test_namespace_reason_absent_for_normal_ns(self) -> None:
        rs = score("get", "pods", "default")
        assert not any("kube-system" in r for r in rs.reasons)
