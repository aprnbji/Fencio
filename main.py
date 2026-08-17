import os
from datetime import datetime, timezone
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from src.analyze import analyze_node
from src.attack import attack_node
from src.distill import distill_node
from src.recon import recon_node
from src.schemas import ReconResult, VulnerabilityReport

TARGETS = [
    {"port": 7001, "name": "SecureBot",      "rating": "HARDENED"},
    {"port": 7002, "name": "HelperBot",       "rating": "WEAK"},
    {"port": 7003, "name": "LegacyBot",       "rating": "CRITICAL"},
    {"port": 7004, "name": "CodeBot",         "rating": "VULNERABLE"},
    {"port": 7005, "name": "RAGBot",          "rating": "WEAK"},
    {"port": 7006, "name": "VisionBot",       "rating": "WEAK"},
    {"port": 7007, "name": "MemoryBot",       "rating": "VULNERABLE"},
    {"port": 7008, "name": "LongwindBot",     "rating": "WEAK"},
    {"port": 7014, "name": "RAGBot-AIM",      "rating": "WEAK"},
    {"port": 7015, "name": "ResearchBot",     "rating": "WEAK"},
    {"port": 7016, "name": "ResearchBot-AIM", "rating": "WEAK"},
    {"port": 7017, "name": "FlightBot",       "rating": "WEAK"},
    {"port": 7018, "name": "FlightBot-AIM",   "rating": "WEAK"},
    {"port": 7022, "name": "RepoBot",         "rating": "WEAK"},
    {"port": 7023, "name": "RepoBot-AIM",     "rating": "WEAK"},
]


class State(TypedDict, total=False):
    session_id: str
    recon_data: ReconResult
    analysis: VulnerabilityReport
    ordered_classes: list[dict]
    findings: list[dict]
    attacker_traces: list[dict]
    distill_count: int


graph = StateGraph(State)
graph.add_node("recon", recon_node)
graph.add_node("analyze", analyze_node)
graph.add_node("attack", attack_node)
graph.add_node("distill", distill_node)
graph.add_edge(START, "recon")
graph.add_edge("recon", "analyze")
graph.add_edge("analyze", "attack")
graph.add_edge("attack", "distill")
graph.add_edge("distill", END)
app = graph.compile()


def run_target(target: dict) -> dict:
    url = f"http://localhost:{target['port']}/v1/chat/completions"
    os.environ["TARGET_URL"] = url

    session_id = f"{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{target['name']}"

    print()
    print("=" * 52)
    print(f"  Target: {target['name']} (port {target['port']}) — {target['rating']}")
    print("=" * 52)
    print()
    print("  Starting Security Assessment...")
    print()

    result = app.invoke({"session_id": session_id})

    findings = result.get("findings", [])
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        sev = f.get("severity", "Low")
        if sev in counts:
            counts[sev] += 1

    print()
    print(f"  Assessment Complete — {target['name']}")
    for sev in ("Critical", "High", "Medium", "Low"):
        if counts[sev]:
            print(f"    {sev}: {counts[sev]}")
    print("  Report generated.")

    return {"target": target, "findings": findings, "counts": counts}


if __name__ == "__main__":
    all_results = []

    for target in TARGETS:
        result = run_target(target)
        all_results.append(result)

    print()
    print("=" * 52)
    print("  Full Engagement Summary")
    print("=" * 52)
    for r in all_results:
        t = r["target"]
        c = r["counts"]
        total = sum(c.values())
        finding_str = f"Cr:{c['Critical']} Hi:{c['High']} Me:{c['Medium']} Lo:{c['Low']}"
        print(f"  {t['name']:<20} port {t['port']}  {finding_str}  ({total} total)")
    print()
