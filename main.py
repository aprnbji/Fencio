from typing import TypedDict
from datetime import datetime

from langgraph.graph import END, START, StateGraph

from src.analyze import analyze_node
from src.attack import attack_node
from src.distill import distill_node
from src.recon import recon_node
from src.schemas import ReconResult, VulnerabilityReport


class State(TypedDict, total=False):
    session_id: str
    recon_data: ReconResult
    analysis: VulnerabilityReport
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

if __name__ == "__main__":
    print("[graph] starting run")
    result = app.invoke({"session_id": datetime.now().strftime("%Y%m%d_%H%M%S")})
    print("[graph] finished")

    print("\nVulnerability Report")
    print(result["analysis"].model_dump_json(indent=2))

    findings = result.get("findings", [])
    print(f"\nAttack Findings ({len(findings)} confirmed)")
    for f in findings:
        print(f"  [{f['severity']}] {f['vulnerability']}")
