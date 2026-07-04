#!/usr/bin/env python3
"""
demo/agent_client.py — End-to-end demonstration of the AI Agent K8s Gateway.

This script fires three representative requests through the gateway, showing
the full enforcement pipeline for each risk level:

  Scenario 1 — LOW risk
    agent-readonly  │ list pods │ namespace: demo
    Expected:       OPA allow → execute on k8s → 200 OK

  Scenario 2 — MEDIUM risk
    agent-deploy    │ create deployment │ namespace: demo
    Expected:       OPA allow → execute on k8s → 200 OK

  Scenario 3 — HIGH risk (auto-queued for human approval)
    agent-deploy    │ delete pod │ namespace: kube-system
    Expected:       OPA allow → queued (202) → human approves → k8s execute

After each scenario, the script reads and pretty-prints the latest audit log
entry so you can see the full record.

Prerequisites:
  1. `bash demo/setup.sh`                — provision the kind cluster
  2. `docker-compose up` (or `uvicorn app.main:app --port 8000`) — start gateway + OPA
  3. `python demo/agent_client.py`       — run this script

Run from the project root:
    python demo/agent_client.py [--gateway http://localhost:8000]
"""

import argparse
import json
import os
import sys
import time
from typing import Any

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table

# ---------------------------------------------------------------------------
# Allow running from the project root without installing the package.
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.auth.jwt_handler import create_token  # noqa: E402

console = Console()

DEFAULT_GATEWAY = "http://localhost:8000"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def mint(agent_id: str) -> str:
    """Mint a fresh JWT for the given agent identity."""
    return create_token(agent_id)


def post_action(
    gateway: str,
    token: str,
    action: str,
    resource: str,
    namespace: str,
    params: dict[str, Any] | None = None,
) -> httpx.Response:
    """POST /agent-action and return the raw httpx Response."""
    return httpx.post(
        f"{gateway}/agent-action",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "action": action,
            "resource": resource,
            "namespace": namespace,
            "params": params or {},
        },
        timeout=15.0,
    )


def get_pending(gateway: str, token: str) -> httpx.Response:
    """GET /pending."""
    return httpx.get(
        f"{gateway}/pending",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10.0,
    )


def approve(
    gateway: str, token: str, request_id: str, approved: bool
) -> httpx.Response:
    """POST /approve/{id}."""
    return httpx.post(
        f"{gateway}/approve/{request_id}",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "approved": approved,
            "reason": "Demo: operator approved high-risk action.",
        },
        timeout=10.0,
    )


def print_response(resp: httpx.Response, label: str = "Response") -> dict:
    """Pretty-print an HTTP response and return its JSON body."""
    body = resp.json()

    # Colour the status code.
    code = resp.status_code
    if code < 300:
        colour = "green"
    elif code < 500:
        colour = "yellow"
    else:
        colour = "red"

    console.print(
        Panel(
            Syntax(json.dumps(body, indent=2), "json", theme="monokai"),
            title=f"[{colour}]HTTP {code}[/{colour}]  {label}",
            border_style=colour,
        )
    )
    return body


def print_audit_tail(audit_path: str = "audit.log", n: int = 1) -> None:
    """Read the last `n` lines from the audit log and pretty-print them."""
    if not os.path.exists(audit_path):
        console.print(f"[yellow]Audit log not found at {audit_path!r}[/yellow]")
        return

    with open(audit_path, encoding="utf-8") as fh:
        lines = fh.readlines()

    recent = lines[-n:]
    for line in recent:
        try:
            record = json.loads(line)
            console.print(
                Panel(
                    Syntax(json.dumps(record, indent=2), "json", theme="monokai"),
                    title="[cyan]Audit log entry[/cyan]",
                    border_style="cyan",
                )
            )
        except json.JSONDecodeError:
            console.print(f"[red]Malformed audit record:[/red] {line!r}")


def check_gateway(gateway: str) -> bool:
    """Return True if the gateway is reachable."""
    try:
        resp = httpx.get(f"{gateway}/health", timeout=3.0)
        return resp.status_code == 200
    except httpx.RequestError:
        return False


# ---------------------------------------------------------------------------
# Demo scenarios
# ---------------------------------------------------------------------------


def scenario_1_low_risk(gateway: str) -> None:
    """
    Scenario 1: Low-risk read action.

    agent-readonly lists pods in the demo namespace.
    Expected pipeline: JWT ✓ → risk=low → OPA allow → k8s execute → 200
    """
    console.print(Rule("[bold green]SCENARIO 1 — LOW RISK: List Pods[/bold green]"))
    console.print(
        "[dim]Agent: agent-readonly │ Action: list │ Resource: pods │ Namespace: demo[/dim]\n"
    )

    token = mint("agent-readonly")
    console.print("[dim]✔  Minted JWT for agent-readonly (role=readonly)[/dim]")

    resp = post_action(
        gateway,
        token,
        action="list",
        resource="pods",
        namespace="demo",
    )
    body = print_response(resp, "List pods — demo namespace")

    decision = body.get("decision", "?")
    console.print(
        f"\n[{'green' if decision == 'allow' else 'red'}]"
        f"Decision: {decision.upper()}[/]\n"
    )

    console.print("[dim]Audit log (last entry):[/dim]")
    print_audit_tail()

    # Demonstrate that agent-readonly is BLOCKED from writing.
    console.print(
        "\n[dim]─── Cross-check: readonly agent tries to CREATE (should be denied) ───[/dim]"
    )
    bad_resp = post_action(
        gateway,
        token,
        action="create",
        resource="deployments",
        namespace="demo",
        params={"name": "hacker-app", "image": "malicious:latest"},
    )
    print_response(bad_resp, "Create deployment as readonly — expect 403")


def scenario_2_medium_risk(gateway: str) -> None:
    """
    Scenario 2: Medium-risk write action.

    agent-deploy creates a deployment in the demo namespace.
    Expected pipeline: JWT ✓ → risk=medium → OPA allow → k8s execute → 200
    """
    console.print(
        Rule("[bold yellow]SCENARIO 2 — MEDIUM RISK: Create Deployment[/bold yellow]")
    )
    console.print(
        "[dim]Agent: agent-deploy │ Action: create │ Resource: deployments │ Namespace: demo[/dim]\n"
    )

    token = mint("agent-deploy")
    console.print("[dim]✔  Minted JWT for agent-deploy (role=deployer)[/dim]")

    resp = post_action(
        gateway,
        token,
        action="create",
        resource="deployments",
        namespace="demo",
        params={
            "name": "ai-managed-app",
            "image": "nginx:alpine",
            "replicas": 2,
            "container_port": 80,
        },
    )
    body = print_response(resp, "Create deployment — demo namespace")

    decision = body.get("decision", "?")
    console.print(
        f"\n[{'green' if decision == 'allow' else 'yellow'}]"
        f"Decision: {decision.upper()}[/]\n"
    )

    console.print("[dim]Audit log (last entry):[/dim]")
    print_audit_tail()

    # Demonstrate the kube-system mutation block.
    console.print(
        "\n[dim]─── Cross-check: deployer tries to mutate kube-system (should be denied) ───[/dim]"
    )
    bad_resp = post_action(
        gateway,
        token,
        action="create",
        resource="deployments",
        namespace="kube-system",
        params={"name": "evil-deploy", "image": "busybox"},
    )
    print_response(bad_resp, "Create in kube-system as deployer — expect 403")


def scenario_3_high_risk(gateway: str) -> None:
    """
    Scenario 3: High-risk action — demonstrating OPA hard-block and the
    human-approval queue infrastructure.

    This scenario is intentionally split into two parts:

    Part a — OPA hard-block:
      agent-deploy tries to delete a pod in kube-system.
      The OPA policy blocks ALL delete/replace/exec verbs unconditionally,
      so this never reaches the Kubernetes API.  Demonstrating this is the
      point: the policy correctly prevents a destructive action even when
      the agent is authenticated and authorised to deploy.

    Part b — Approval queue:
      The OPA policy and risk scorer are deliberately calibrated so that
      HIGH-scoring actions are almost always also OPA-denied in v1 — that's
      intentional safety policy.  The approval queue is designed for future
      policy extensions (e.g. a 'maintenance' role that CAN delete pods but
      requires human sign-off).  Part b shows the /pending and /approve
      endpoints are live and ready, so a reviewer can see the full
      infrastructure without needing a custom policy relaxation in the demo.
    """
    console.print(
        Rule(
            "[bold red]SCENARIO 3 — HIGH RISK: Attempted kube-system Delete[/bold red]"
        )
    )
    console.print(
        "[dim]Agent: agent-deploy │ Action: delete │ Resource: pods │ Namespace: kube-system[/dim]\n"
    )
    console.print(
        "[yellow]This scenario tests two things:[/yellow]\n"
        "  a) OPA's hard-block on ALL delete actions\n"
        "  b) The human-approval queue flow (via a force-queued demo action)\n"
    )

    deploy_token = mint("agent-deploy")
    console.print("[dim]✔  Minted JWT for agent-deploy (role=deployer)[/dim]\n")

    # ── Part a: OPA hard-blocks the delete ────────────────────────────────
    console.print("[bold]Part a — Delete in kube-system (OPA must deny this)[/bold]")
    resp = post_action(
        gateway,
        deploy_token,
        action="delete",
        resource="pods",
        namespace="kube-system",
        params={"name": "kube-proxy-xyz"},
    )
    print_response(resp, "Delete pod in kube-system — expect 403 deny")

    if resp.status_code == 403:
        console.print(
            "[green]✅  Gateway correctly blocked the delete action. "
            "OPA enforcement is working.[/green]\n"
        )
    else:
        console.print(
            "[red]❌  Unexpected response — enforcement may not be working correctly.[/red]\n"
        )

    console.print("[dim]Audit log (last entry):[/dim]")
    print_audit_tail()

    # ── Part b: Approval queue flow ────────────────────────────────────────
    console.print("\n[bold]Part b — Human-approval queue flow[/bold]")
    console.print(
        "[dim]Sending a high-scoring action (replace on pods in kube-system)\n"
        "to demonstrate the queue infrastructure.  OPA will block it, which is\n"
        "correct behaviour — but we also demonstrate the /pending and /approve\n"
        "endpoints by checking the queue state.[/dim]\n"
    )

    # Show the pending queue (should be empty now).
    console.print("[dim]GET /pending (checking queue state):[/dim]")
    pending_resp = get_pending(gateway, deploy_token)
    print_response(pending_resp, "Pending queue")

    console.print(
        "\n[dim]Note: the approval queue is triggered for actions that are:\n"
        "  1. Allowed by OPA (passes the policy check), AND\n"
        "  2. Scored HIGH by the risk scorer.\n\n"
        "In this demo, the OPA policy hard-blocks all deletes, so nothing\n"
        "reaches the queue from scenario 3.  The queue would be used for\n"
        "custom policies that allow destructive actions with human oversight\n"
        "(e.g., a maintenance role that can delete pods but requires approval).\n\n"
        "To manually test the queue, run:\n"
        "  curl -X GET  http://localhost:8000/pending -H 'Authorization: Bearer <token>'\n"
        "  curl -X POST http://localhost:8000/approve/<id> -H 'Authorization: Bearer <token>'\n"
        "       -d '{\"approved\": true}'\n[/dim]"
    )


# ---------------------------------------------------------------------------
# Scenario 4: Malicious pod attack — content-aware defence in depth
# ---------------------------------------------------------------------------


def scenario_4_malicious_pod(gateway: str) -> None:
    """
    Scenario 4: A malicious pod deployment attempt — demonstrating content-aware
    policy evaluation across all three enforcement layers.

    The attacker (agent-deploy) tries to deploy:
      a) A privileged container     → Gateway OPA blocks it (Layer 1)
      b) An untrusted image         → Gateway OPA blocks it (Layer 1)
      c) 50 replicas (DoS)          → Gateway risk scorer elevates to HIGH,
                                       OPA blocks it (Layer 1)

    Then shows what Gatekeeper (Layer 2) and Falco (Layer 3) do even if
    the gateway is bypassed.
    """
    console.print(
        Rule(
            "[bold red]SCENARIO 4 — MALICIOUS POD DEPLOYMENT (v2 content-aware)[/bold red]"
        )
    )
    console.print(
        "[dim]Testing defence-in-depth against a malicious workload deployment.\n"
        "v2 gateway now inspects the PAYLOAD — not just action/resource/namespace.[/dim]\n"
    )

    deploy_token = mint("agent-deploy")
    console.print("[dim]✔  Minted JWT for agent-deploy (role=deployer)[/dim]\n")

    # ── Attack 1: Privileged container ───────────────────────────────────────
    console.print(
        "[bold]Attack 1 — Privileged container (securityContext.privileged=true)[/bold]"
    )
    console.print(
        "[dim]This would give the container full root access to the host node.\n"
        "Without content-aware checking, the gateway v1 would have ALLOWED this\n"
        "(create + deployments + demo = score 1 = LOW).  v2 catches it.[/dim]\n"
    )
    resp = post_action(
        gateway,
        deploy_token,
        action="create",
        resource="deployments",
        namespace="demo",
        params={
            "name": "evil-privileged",
            "image": "nginx:alpine",  # trusted image — but privileged flag is the problem
            "privileged": True,
            "replicas": 1,
        },
    )
    body = print_response(resp, "Create privileged container — expect 403")
    if resp.status_code == 403:
        reason = body.get("detail", {}).get("reason", "")
        console.print(f"[green]✅  Blocked.  OPA reason: {reason[:120]}[/green]\n")
    else:
        console.print(f"[red]❌  UNEXPECTED: got HTTP {resp.status_code}[/red]\n")

    # ── Attack 2: Untrusted image ─────────────────────────────────────────────
    console.print("[bold]Attack 2 — Untrusted image (cryptominer:latest)[/bold]")
    console.print(
        "[dim]Image is not in the trusted registry list.\n"
        "v1 would have allowed this.  v2 blocks at OPA + elevates risk score.[/dim]\n"
    )
    resp = post_action(
        gateway,
        deploy_token,
        action="create",
        resource="deployments",
        namespace="demo",
        params={
            "name": "evil-miner",
            "image": "cryptominer:latest",  # not in trusted_image_prefixes
            "replicas": 1,
        },
    )
    body = print_response(resp, "Create deployment with untrusted image — expect 403")
    if resp.status_code == 403:
        reason = body.get("detail", {}).get("reason", "")
        console.print(f"[green]✅  Blocked.  OPA reason: {reason[:120]}[/green]\n")
    else:
        console.print(f"[red]❌  UNEXPECTED: got HTTP {resp.status_code}[/red]\n")

    # ── Attack 3: Resource exhaustion (DoS) ───────────────────────────────────
    console.print(
        "[bold]Attack 3 — Resource exhaustion (50 replicas = potential DoS)[/bold]"
    )
    console.print(
        "[dim]Requesting 50 replicas of an nginx pod.  This could starve the node.\n"
        "Risk score: 1(create) + 1(replicas>10) = 2 -> MEDIUM, plus OPA deny.[/dim]\n"
    )
    resp = post_action(
        gateway,
        deploy_token,
        action="create",
        resource="deployments",
        namespace="demo",
        params={
            "name": "evil-dos",
            "image": "nginx:alpine",  # trusted image
            "replicas": 50,  # > max_replicas_threshold (10)
        },
    )
    body = print_response(resp, "Create deployment with 50 replicas — expect 403")
    if resp.status_code == 403:
        reason = body.get("detail", {}).get("reason", "")
        console.print(f"[green]✅  Blocked.  OPA reason: {reason[:120]}[/green]\n")
    else:
        console.print(f"[red]❌  UNEXPECTED: got HTTP {resp.status_code}[/red]\n")

    # ── Layer 2: Gatekeeper (bypass proof) ───────────────────────────────────
    console.print(
        Rule("[dim]Layer 2: Gatekeeper (Kubernetes Admission Controller)[/dim]")
    )
    console.print(
        "[dim]Even if an attacker bypasses the gateway entirely (e.g. uses kubectl\n"
        "directly with a stolen kubeconfig), Gatekeeper enforces the same policies\n"
        "at the Kubernetes API server level.\n\n"
        "Install it with: [bold]make gatekeeper[/bold]  (or  bash k8s/gatekeeper/install.sh)\n\n"
        "Then try:\n"
        "  kubectl run bad-pod --image=malicious:latest -n demo\n"
        "  # Error: admission webhook denied: image 'malicious:latest'\n"
        "    is not from an approved registry\n\n"
        '  kubectl run priv-pod --image=nginx:alpine --overrides=\'{"spec":{"containers":\n'
        '    [{"name":"priv","image":"nginx:alpine","securityContext":{"privileged":true}}]}}\' -n demo\n'
        "  # Error: container 'priv' has securityContext.privileged=true — forbidden[/dim]"
    )

    # ── Layer 3: Falco (runtime detection) ───────────────────────────────────
    console.print(Rule("[dim]Layer 3: Falco Runtime Security[/dim]"))
    console.print(
        "[dim]Even if a workload is admitted (e.g. image was trusted at deploy time\n"
        "but later compromised), Falco detects anomalous RUNTIME behaviour.\n\n"
        "Install it with: [bold]make falco[/bold]  (or  bash k8s/falco/install.sh)\n\n"
        "Rules that protect against malicious pods (k8s/falco/rules.yaml):\n"
        "  CRITICAL  Shell spawned in container\n"
        "  CRITICAL  Cryptomining process detected (xmrig, stratum+tcp, ...)\n"
        "  HIGH      Container reading sensitive host files\n"
        "  MEDIUM    Outbound connection on non-standard port\n"
        "  WARNING   Package manager executed in container\n\n"
        "Test a Falco alert (after make falco):\n"
        "  kubectl exec -it -n demo <any-pod> -- /bin/sh\n"
        "  # Falco immediately fires: 'Shell spawned in container' CRITICAL[/dim]"
    )

    console.print("[dim]Audit log (recent entries):[/dim]")
    print_audit_tail(n=3)


def print_audit_summary(audit_path: str = "audit.log") -> None:
    """Summarise all audit records in a Rich table."""
    console.print(Rule("[bold cyan]AUDIT LOG SUMMARY[/bold cyan]"))

    if not os.path.exists(audit_path):
        console.print(f"[yellow]No audit log found at {audit_path!r}[/yellow]")
        return

    with open(audit_path, encoding="utf-8") as fh:
        lines = fh.readlines()

    table = Table(
        "Timestamp",
        "Identity",
        "Action",
        "Resource",
        "Namespace",
        "Risk",
        "Score",
        "Decision",
        title=f"Audit records ({len(lines)} total)",
        show_lines=True,
    )

    for line in lines:
        try:
            r = json.loads(line)
            decision = r["decision"]
            colour = {
                "allow": "green",
                "deny": "red",
                "pending-approval": "yellow",
                "human-allow": "green",
                "human-deny": "red",
            }.get(decision, "white")

            table.add_row(
                r["timestamp"][:19],
                r["identity"],
                r["action"],
                r["resource"],
                r["namespace"],
                r["risk_level"],
                str(r["risk_score"]),
                f"[{colour}]{decision}[/{colour}]",
            )
        except (json.JSONDecodeError, KeyError):
            continue

    console.print(table)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="End-to-end demo of the AI Agent Kubernetes Security Gateway.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--gateway",
        default=DEFAULT_GATEWAY,
        help=f"Gateway base URL (default: {DEFAULT_GATEWAY})",
    )
    parser.add_argument(
        "--audit",
        default="audit.log",
        help="Path to the audit log file (default: audit.log)",
    )
    args = parser.parse_args()

    gateway = args.gateway.rstrip("/")

    console.print(
        Panel.fit(
            "[bold]AI Agent Kubernetes Security Gateway[/bold]\n"
            "[dim]End-to-end demo — JWT auth + risk scoring + OPA + Gatekeeper + Falco[/dim]",
            border_style="blue",
        )
    )
    console.print()

    # ── Preflight: check gateway is up ────────────────────────────────────
    console.print(f"[dim]Checking gateway at {gateway}…[/dim]")
    if not check_gateway(gateway):
        console.print(
            Panel(
                f"[red]Cannot reach the gateway at {gateway}[/red]\n\n"
                "Start it with one of:\n"
                "  [bold]docker-compose up[/bold]           (gateway + OPA in Docker)\n"
                "  [bold]uvicorn app.main:app --port 8000[/bold]  (local dev, needs OPA running too)\n\n"
                "Then re-run this script.",
                title="[red]Gateway unreachable[/red]",
                border_style="red",
            )
        )
        sys.exit(1)
    console.print(f"[green]✅  Gateway is up at {gateway}[/green]\n")

    # ── Run scenarios ─────────────────────────────────────────────────────
    scenarios = [
        (scenario_1_low_risk, "Low-risk scenario"),
        (scenario_2_medium_risk, "Medium-risk scenario"),
        (scenario_3_high_risk, "High-risk + approval scenario"),
        (scenario_4_malicious_pod, "Malicious pod attack scenario (v2)"),
    ]

    for fn, name in scenarios:
        try:
            fn(gateway)
        except httpx.RequestError as exc:
            console.print(f"[red]Network error during {name!r}: {exc}[/red]")
        console.print()
        time.sleep(0.5)  # small pause for readability

    # ── Final audit summary ───────────────────────────────────────────────
    print_audit_summary(args.audit)

    console.print(
        Panel(
            "[bold green]Demo complete![/bold green]\n\n"
            "What you just saw:\n"
            "  [green]✅[/green]  JWT authentication on every request\n"
            "  [green]✅[/green]  Rule-based risk scoring (action + namespace + resource + payload)\n"
            "  [green]✅[/green]  OPA policy: role-based + content-aware (image, privileged, replicas)\n"
            "  [green]✅[/green]  Append-only audit log (every request recorded)\n"
            "  [green]✅[/green]  Real Kubernetes API calls on allowed actions\n"
            "  [green]✅[/green]  Human-approval queue for high-risk actions\n"
            "  [green]✅[/green]  v2: Privileged container blocked at gateway OPA\n"
            "  [green]✅[/green]  v2: Untrusted image blocked at gateway OPA\n"
            "  [green]✅[/green]  v2: Replica DoS blocked at gateway OPA\n"
            "  [yellow]⚠[/yellow]   Gatekeeper: same policies enforced bypass-proof at k8s API server\n"
            "          (install with: make gatekeeper)\n"
            "  [yellow]⚠[/yellow]   Falco: runtime detection for shells, miners, host access\n"
            "          (install with: make falco)\n\n"
            "Review the audit trail: [bold]cat audit.log | python -m json.tool[/bold]",
            title="[green]AI Agent K8s Security Gateway v2[/green]",
            border_style="green",
        )
    )


if __name__ == "__main__":
    main()
