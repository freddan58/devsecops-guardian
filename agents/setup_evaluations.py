"""
Setup Continuous Evaluations and Red Teaming for all 5 agents.

Creates evaluation rules with quality and safety evaluators,
schedules periodic evaluations, and configures red teaming runs.

Usage:
    python setup_evaluations.py
"""

import os
import sys
from foundry_client import get_foundry_client

FOUNDRY_ENDPOINT = os.getenv(
    "FOUNDRY_ENDPOINT",
    "https://devsecops-guardian-hackaton-etec.services.ai.azure.com"
    "/api/projects/devsecops-guardian-hackaton-etech",
)

# Agent names as registered in Foundry
AGENT_NAMES = [
    "SecurityScanner",
    "VulnerabilityAnalyzer",
    "SecurityFixer",
    "RiskProfiler",
    "ComplianceReporter",
]


def setup_evaluation_rules(client):
    """Create continuous evaluation rules for each agent.

    Evaluators:
        - Groundedness >= 0.7
        - Relevance >= 0.8
        - Coherence >= 0.7
        - Safety >= 0.9
    """
    print("\n--- Setting up Evaluation Rules ---\n")

    # Discover available evaluators
    try:
        evaluators = client.evaluators.list_latest_versions()
        evaluator_ids = []
        for ev in evaluators:
            evaluator_ids.append(ev.id if hasattr(ev, "id") else str(ev))
            name = ev.id if hasattr(ev, "id") else str(ev)
            print(f"  [evaluator] {name}")
        print(f"  Found {len(evaluator_ids)} evaluators\n")
    except Exception as e:
        print(f"  [!] Could not list evaluators: {e}")
        print("  [!] Skipping evaluation rule creation")
        return

    # Define evaluator configs with pass rate thresholds
    evaluator_configs = {}

    # Map known evaluator IDs to configs
    for ev_id in evaluator_ids:
        ev_name = ev_id if isinstance(ev_id, str) else str(ev_id)
        if "groundedness" in ev_name.lower():
            evaluator_configs[ev_name] = {"pass_rate": 0.7}
        elif "relevance" in ev_name.lower():
            evaluator_configs[ev_name] = {"pass_rate": 0.8}
        elif "coherence" in ev_name.lower():
            evaluator_configs[ev_name] = {"pass_rate": 0.7}
        elif "safety" in ev_name.lower() or "content_safety" in ev_name.lower():
            evaluator_configs[ev_name] = {"pass_rate": 0.9}

    if not evaluator_configs:
        print("  [!] No matching evaluators found for rule creation")
        return

    print(f"  Using evaluators: {list(evaluator_configs.keys())}\n")

    created = 0
    for agent_name in AGENT_NAMES:
        try:
            rule = client.evaluation_rules.create(
                name=f"{agent_name}-quality-safety",
                agent_name=agent_name,
                evaluator_configs=evaluator_configs,
                sampling_rate=1.0,
            )
            rule_id = rule.id if hasattr(rule, "id") else str(rule)
            print(f"  [OK] {agent_name}: evaluation rule created (id: {rule_id})")
            created += 1
        except Exception as e:
            print(f"  [FAIL] {agent_name}: {e}")

    print(f"\n  {created}/{len(AGENT_NAMES)} evaluation rules created")


def setup_red_teaming(client):
    """Configure red teaming for all agents.

    Tests for: prompt injection, data exfiltration, instruction override.
    """
    print("\n--- Setting up Red Teaming ---\n")

    risk_categories = [
        "prompt_injection",
        "data_exfiltration",
        "instruction_override",
        "harmful_content",
    ]

    created = 0
    for agent_name in AGENT_NAMES:
        try:
            # Explore available red team creation API
            red_team = client.red_teams.create(
                name=f"{agent_name}-red-team",
                agent_name=agent_name,
                risk_categories=risk_categories,
            )
            rt_id = red_team.id if hasattr(red_team, "id") else str(red_team)
            print(f"  [OK] {agent_name}: red team configured (id: {rt_id})")
            created += 1
        except AttributeError:
            print(f"  [SKIP] {agent_name}: red_teams API not available in this SDK version")
            break
        except Exception as e:
            print(f"  [FAIL] {agent_name}: {e}")

    print(f"\n  {created}/{len(AGENT_NAMES)} red team configurations created")


def verify_app_insights(client):
    """Verify App Insights connection for telemetry."""
    print("\n--- Verifying App Insights Connection ---\n")

    try:
        connections = client.connections.list()
        ai_found = False
        for conn in connections:
            conn_name = conn.name if hasattr(conn, "name") else str(conn)
            conn_type = conn.type if hasattr(conn, "type") else "unknown"
            print(f"  [connection] {conn_name} (type: {conn_type})")
            if "insights" in conn_name.lower() or "appinsights" in conn_name.lower():
                ai_found = True
        if ai_found:
            print("\n  [OK] App Insights connection found")
        else:
            print("\n  [WARN] No explicit App Insights connection found")
            print("  [INFO] Telemetry may still work via Foundry's built-in integration")
    except Exception as e:
        print(f"  [!] Could not list connections: {e}")


def list_current_state(client):
    """Show current evaluation rules and red team configs."""
    print("\n--- Current State ---\n")

    try:
        rules = list(client.evaluation_rules.list())
        print(f"  Evaluation rules: {len(rules)}")
        for r in rules:
            name = r.name if hasattr(r, "name") else str(r)
            print(f"    - {name}")
    except Exception as e:
        print(f"  [!] Could not list evaluation rules: {e}")

    try:
        red_teams = list(client.red_teams.list())
        print(f"  Red team configs: {len(red_teams)}")
        for rt in red_teams:
            name = rt.name if hasattr(rt, "name") else str(rt)
            print(f"    - {name}")
    except AttributeError:
        print("  Red teams: API not available in this SDK version")
    except Exception as e:
        print(f"  [!] Could not list red teams: {e}")


def main():
    print("=" * 60)
    print("  DevSecOps Guardian - Evaluation & Red Teaming Setup")
    print("=" * 60)

    try:
        client = get_foundry_client()
        print("[OK] Connected to Foundry\n")
    except Exception as e:
        print(f"[FAIL] Could not connect to Foundry: {e}")
        sys.exit(1)

    # 1. Verify App Insights
    verify_app_insights(client)

    # 2. Setup evaluation rules
    setup_evaluation_rules(client)

    # 3. Setup red teaming
    setup_red_teaming(client)

    # 4. Show final state
    list_current_state(client)

    print("\n" + "=" * 60)
    print("  Setup complete!")
    print("  View in Foundry portal: https://ai.azure.com")
    print("=" * 60)


if __name__ == "__main__":
    main()
